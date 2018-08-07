package consulacl

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	consul "github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
)

const (
	FieldName  = "name"
	FieldToken = "token"
	FieldType  = "type"

	FieldRule = "rule"

	FieldScope  = "scope"
	FieldPrefix = "prefix"
	FieldPolicy = "policy"

	FieldInherits = "inherits"
)

var prefixedScopes = []string{"agent", "event", "key", "node", "query", "service", "session"}
var singletonScopes = []string{"keyring", "operator"}

func resourceConsulACLToken() *schema.Resource {
	var allScopes []string
	allScopes = append(allScopes, prefixedScopes...)
	allScopes = append(allScopes, singletonScopes...)

	return &schema.Resource{
		Create: resourceConsulACLTokenCreate,
		Update: resourceConsulACLTokenUpdate,
		Read:   resourceConsulACLTokenRead,
		Delete: resourceConsulACLTokenDelete,

		Importer: &schema.ResourceImporter{
			State: func(d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
				d.Set(FieldToken, d.Id())
				d.SetId(getSHA256(d.Id()))
				return []*schema.ResourceData{d}, nil
			},
		},

		CustomizeDiff: diffResource,

		Schema: map[string]*schema.Schema{
			FieldName: {
				Type:     schema.TypeString,
				Required: true,
			},

			FieldRule: {
				Type:     schema.TypeSet,
				Optional: true,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						FieldScope: {
							Type: schema.TypeString,
							// it's required but we have to enforce otherwise due to a bug in terraform
							// when injecting rules as
							// rule = ["${data.null_data_source.policy.*.outputs}"]
							Computed:     true,
							Optional:     true,
							ValidateFunc: validation.StringInSlice(allScopes, true),
						},
						FieldPrefix: {
							Type:     schema.TypeString,
							Computed: true,
							Optional: true,
						},
						FieldPolicy: {
							Type: schema.TypeString,
							// it's required but we have to enforce otherwise due to a bug in terraform
							// when injecting rules as
							// rule = ["${data.null_data_source.policy.*.outputs}"]
							Computed: true,
							Optional: true,
						},
					},
				},
			},

			FieldToken: {
				Type:      schema.TypeString,
				Computed:  true,
				Optional:  true,
				Sensitive: true,
			},

			FieldType: {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringInSlice([]string{"client", "management"}, true),
			},

			FieldInherits: &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func resourceConsulACLTokenCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*consul.Client)

	rules, err := extractRules(d.Get(FieldRule).(*schema.Set).List())
	if err != nil {
		return err
	}

	// We have to get a list of all the ACLs currently in Consul
	// Since we don't know the token string for exising acls,
	// we need to parse them out, so we can reference by name
	// We can also use this to enforce unique names
	allACLs, _, err := client.ACL().List(nil)

	if err != nil {
		return err
	}

	for _, acls := range allACLs {

		if acls.Name == d.Get(FieldName).(string) {
			// Don't have duplicate token names
			return errors.New("There is already a token with this name")
		}

	}

	var inheritedRules string

	if len(d.Get("inherits").([]interface{})) > 0 {

		inherits := reflect.ValueOf(d.Get("inherits"))
		for i := 0; i < inherits.Len(); i++ {
			inheritString := inherits.Index(i).Interface().(string)

			var aclToken string

			for _, acls := range allACLs {

				if acls.Name == inheritString {
					aclToken = acls.ID
					break
				}

			}

			acl, _, errClient := client.ACL().Info(aclToken, nil)

			if errClient != nil {
				return errClient
			}

			inheritedRules = inheritedRules + "\n" + acl.Rules
		}
		rules, _ = dedupeRules(encodeRules(rules), inheritedRules)
	}

	var acl *consul.ACLEntry

	acl = &consul.ACLEntry{
		ID:    d.Get(FieldToken).(string),
		Name:  d.Get(FieldName).(string),
		Type:  d.Get(FieldType).(string),
		Rules: encodeRules(rules),
	}

	token, _, err := client.ACL().Create(acl, nil)
	if err != nil {
		return err
	}

	d.SetId(getSHA256(token))
	d.Set(FieldToken, token)
	return resourceConsulACLTokenRead(d, meta)
}

func resourceConsulACLTokenRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*consul.Client)

	/*_, err := extractRules(d.Get(FieldRule).(*schema.Set).List())
	if err != nil {
		return err
	}*/

	acl, _, err := client.ACL().Info(d.Get(FieldToken).(string), nil)
	if err != nil {
		return err
	}

	if acl == nil {
		d.SetId("")
		return nil
	}

	rules, err := decodeRules(acl.Rules)
	if err != nil {
		return err
	}

	d.SetId(getSHA256(acl.ID))
	d.Set(FieldToken, acl.ID)
	d.Set(FieldName, acl.Name)
	d.Set(FieldType, acl.Type)
	d.Set(FieldRule, rules)

	return nil
}

func resourceConsulACLTokenUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*consul.Client)

	rules, err := extractRules(d.Get(FieldRule).(*schema.Set).List())
	if err != nil {
		return err
	}

	if len(d.Get("inherits").([]interface{})) > 0 {
		if d.HasChange("rule") {
			o, n := d.GetChange("rule")
			if o == nil {
				o = new(schema.Set)
			}
			if n == nil {
				n = new(schema.Set)
			}

			os := o.(*schema.Set)
			ns := n.(*schema.Set)

			remove := os.Difference(ns).List()
			add := ns.Difference(os).List()

			a, _ := extractRules(add)
			r, _ := extractRules(remove)

			combinedRules := sortString(encodeRules(a) + "\n" + encodeRules(r))

			rules, _ = decodeRules(combinedRules)
			if err != nil {
				return err
			}

			d.Set(FieldRule, rules)
		}

		var inheritedRules string

		inherits := reflect.ValueOf(d.Get("inherits"))
		for i := 0; i < inherits.Len(); i++ {
			inheritString := inherits.Index(i).Interface().(string)

			var aclToken string

			// We have to get a list of all the ACLs currently in Consul
			// Since we don't know the token string for exising acls,
			// we need to parse them out, so we can reference by name
			allACLs, _, err := client.ACL().List(nil)

			if err != nil {
				return err
			}

			for _, acls := range allACLs {

				if acls.Name == d.Get(FieldName).(string) && d.Get(FieldToken).(string) == "" {
					d.SetId(getSHA256(acls.ID))
					d.Set(FieldToken, acls.ID)
					break
				}

			}

			for _, acls := range allACLs {

				if acls.Name == inheritString {
					aclToken = acls.ID
					break
				}

			}

			acl, _, errClient := client.ACL().Info(aclToken, nil)

			if errClient != nil {
				return errClient
			}

			inheritedRules = inheritedRules + "\n" + acl.Rules
		}


		r := encodeRules(rules)
		rules, _ = dedupeRules(r, inheritedRules)
	}

	acl := &consul.ACLEntry{
		ID:    d.Get(FieldToken).(string),
		Name:  d.Get(FieldName).(string),
		Type:  d.Get(FieldType).(string),
		Rules: encodeRules(rules),
	}

	_, err = client.ACL().Update(acl, nil)
	if err != nil {
		return err
	}

	return resourceConsulACLTokenRead(d, meta)
}

func resourceConsulACLTokenDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*consul.Client)

	_, err := client.ACL().Destroy(d.Get(FieldToken).(string), nil)
	if err != nil {
		return err
	}

	d.SetId("")
	return nil
}

// So this one is really ugly. But it's still more convenient that native HCL struct de-serialization
func decodeRules(raw string) ([]map[string]string, error) {
	var result []map[string]string

	var policies map[string]interface{}

	err := hcl.Decode(&policies, raw)
	if err != nil {
		return nil, err
	}

	for scope, scopeDefinitions := range policies {
		// scopeDefinitions is either of:
		// {"foo/bar":[{"policy":"write"}]}
		// "operator":"read"

		defRef := reflect.ValueOf(scopeDefinitions)

		if defRef.Kind() == reflect.String {
			simplePolicyValue := defRef.String()
			simplePolicy := map[string]string{FieldScope: scope, FieldPolicy: simplePolicyValue}
			result = append(result, simplePolicy)
		} else {

			for i := 0; i < defRef.Len(); i++ {
				scopePolicyRef := defRef.Index(i)

				prefixRef := scopePolicyRef.MapKeys()[0]
				// "foo/bar"
				prefix := prefixRef.String()

				// {"policy":"write"}
				policyMapRef := scopePolicyRef.MapIndex(prefixRef).Elem().Index(0)

				policyMap := make(map[string]string)
				for _, k := range policyMapRef.MapKeys() {
					policyMap[k.String()] = policyMapRef.MapIndex(k).Elem().String()
				}

				policy, ok := policyMap["policy"]
				if ok {
					decodedPolicy := map[string]string{FieldScope: scope, FieldPrefix: prefix, FieldPolicy: policy}
					result = append(result, decodedPolicy)
				}
			}
		}
	}

	return result, nil
}

func dedupeRules(existingRules string, newRules string) ([]map[string]string, error) {
	var allErrors *multierror.Error
	var result []map[string]string
	newRules = sortString(existingRules + newRules)
	allRules, err := decodeRules(newRules)

	if err != nil {
		err := fmt.Errorf("Couldn't decode all the rules")
		allErrors = multierror.Append(allErrors, err)
	}

	for _, i := range allRules {
		found := false
		for jIndex, j := range result {
			// Search through the ones we've already added

			if strings.ToLower(i["scope"]) == strings.ToLower(j["scope"]) {
				if stringInSlice(i["scope"], prefixedScopes) {
					iprefix, iok := i["prefix"]
					jprefix, jok := j["prefix"]
					if iok && jok {
						if iprefix == jprefix {
							if i["policy"] == j["policy"] {
								found = true
							} else if i["policy"] == "read" && j["policy"] == "write" {
								found = true
							} else if (i["policy"] == "read" && j["policy"] == "deny") ||
								(i["policy"] == "write" && j["policy"] == "read") ||
								(i["policy"] == "write" && j["policy"] == "deny") {
								result[jIndex] = i
								found = true
							}
						}
					}
				} else if stringInSlice(i["scope"], singletonScopes) {
					if i["scope"] == j["scope"] {
						found = true
					} else if (i["scope"] == "read" && j["scope"] == "deny") ||
						(i["scope"] == "write" && j["scope"] == "read") ||
						(i["scope"] == "write" && j["scope"] == "deny") {
						result[jIndex] = i
					}
				}
			}
		}
		if found == false {
			result = append(result, i)
		}
	}

	return result, allErrors.ErrorOrNil()
}

// HCL lib does not provide Marshal/Serialize functionality :/
func encodeRules(rules []map[string]string) string {
	var result []string

	for _, rule := range rules {
		policy := strings.ToLower(rule[FieldPolicy])
		scope := strings.ToLower(rule[FieldScope])
		prefix, ok := rule[FieldPrefix]

		var ruleStr string

		if ok {
			ruleStr = fmt.Sprintf("%s \"%s\" { policy = \"%s\" }", scope, strings.ToLower(prefix), policy)
		} else {
			ruleStr = fmt.Sprintf("%s = \"%s\"", scope, policy)
		}
		result = append(result, ruleStr)

	}
	sort.Strings(result)
	result = append(result, "")
	return strings.Join(result, "\n")
}

func extractRules(rawRules []interface{}) ([]map[string]string, error) {
	var allErrors *multierror.Error

	var result []map[string]string
	for _, raw := range rawRules {
		definition := raw.(map[string]interface{})

		scope := definition[FieldScope].(string)
		if scope == "" {
			err := fmt.Errorf("the '%s' field is required in: '%v'", FieldScope, definition)
			allErrors = multierror.Append(allErrors, err)
		}

		policy := definition[FieldPolicy].(string)
		if policy == "" {
			err := fmt.Errorf("the '%s' field is required in: '%v'", FieldPolicy, definition)
			allErrors = multierror.Append(allErrors, err)
		}

		prefix := definition[FieldPrefix].(string)
		rule := map[string]string{FieldScope: scope, FieldPolicy: policy}

		if stringInSlice(scope, prefixedScopes) {
			rule[FieldPrefix] = strings.ToLower(prefix)
		} else if prefix != "" {
			err := fmt.Errorf("the 'prefix' field is not allowed on scopes %s: %v", strings.Join(singletonScopes, ", "), definition)
			allErrors = multierror.Append(allErrors, err)
		}

		result = append(result, rule)
	}

	return result, allErrors.ErrorOrNil()
}

func stringInSlice(str string, list []string) bool {
	for _, elem := range list {
		if elem == str {
			return true
		}
	}
	return false
}

// We only need this to run manual validation on fields
func diffResource(d *schema.ResourceDiff, m interface{}) error {
	_, newRules := d.GetChange(FieldRule)

	_, err := extractRules(newRules.(*schema.Set).List())
	if err != nil {
		return err
	}

	return nil
}

func getSHA256(src string) string {
	h := sha256.New()
	h.Write([]byte(src))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func sortString(w string) string {
	s := strings.Split(w, "\n")
	sort.Strings(s)
	var n []string
	for _, str := range s {
		if str != "" {
			n = append(n, str)
		}
	}
	return strings.Join(n, "\n")
}
