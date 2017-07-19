package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	// "log"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	log "github.com/Sirupsen/logrus"
)

func newFuncMap(ctx *TemplateContext) template.FuncMap {
	return template.FuncMap{
		"cell":               NewCell,
		"concatenateUnique":  concatenateUnique,
		"closest":            arrayClosest,
		"coalesce":           coalesce,
		"contains":           contains,
		"dict":               dict,
		"dir":                dirList,
		"exists":             exists,
		"env":                os.Getenv,
		"formatClean":        formatClean,
		"first":              arrayFirst,
		"filterHost":         filterHost,
		"getAllLabelValue":   getAllLabelValue,
		"groupBy":            groupBy,
		"groupByKeys":        groupByKeys,
		"groupByMulti":       groupByMulti,
		"groupByLabel":       groupByLabel,
		"groupByMultiFilter": groupByMultiFilter,
		"hasPrefix":          hasPrefix,
		"hasSuffix":          hasSuffix,
		"join":               strings.Join,
		"json":               marshalJson,
		"intersect":          intersect,
		"keys":               keys,
		"last":               arrayLast,
		"replace":            strings.Replace,
		"parseBool":          strconv.ParseBool,
		"parseJson":          unmarshalJson,
		"queryEscape":        url.QueryEscape,
		"host":               hostFunc(ctx),
		"hosts":              hostsFunc(ctx),
		"service":            serviceFunc(ctx),
		"services":           servicesFunc(ctx),
		"sha1":               hashSha1,
		"split":              strings.Split,
		"splitN":             strings.SplitN,
		"toUpper":            strings.ToUpper,
		"toLower":            strings.ToLower,
		"timestamp":          time.Now,
		"trimPrefix":         trimPrefix,
		"trimSuffix":         trimSuffix,
		"trim":               trim,
		"when":               when,
		"where":              where,
		"whereExist":         whereExist,
		"whereNotExist":      whereNotExist,
		"whereAny":           whereAny,
		"whereAll":           whereAll,
		"whereLabelExists":   whereLabelExists,
		"whereLabelEquals":   whereLabelEquals,
		"whereLabelMatches":  whereLabelEquals,
		// "whereLabelDoesNotExist": whereLabelDoesNotExist,
		// "whereLabelValueMatches": whereLabelValueMatches,

	}
}

// serviceFunc returns a single service given a string argument in the form
// <service-name>[.<stack-name>].
func serviceFunc(ctx *TemplateContext) func(...string) (interface{}, error) {
	return func(s ...string) (result interface{}, err error) {
		result, err = ctx.GetService(s...)
		if _, ok := err.(NotFoundError); ok {
			log.Debug(err)
			return nil, nil
		}
		return
	}
}

// servicesFunc returns all available services, optionally filtered by stack
// name or label values.
func servicesFunc(ctx *TemplateContext) func(...string) (interface{}, error) {
	return func(s ...string) (interface{}, error) {
		return ctx.GetServices(s...)
	}
}

// hostFunc returns a single host given it's UUID.
func hostFunc(ctx *TemplateContext) func(...string) (interface{}, error) {
	return func(s ...string) (result interface{}, err error) {
		result, err = ctx.GetHost(s...)
		if _, ok := err.(NotFoundError); ok {
			log.Debug(err)
			return nil, nil
		}
		return
	}
}

// hostsFunc returns all available hosts, optionally filtered by label value.
func hostsFunc(ctx *TemplateContext) func(...string) (interface{}, error) {
	return func(s ...string) (interface{}, error) {
		return ctx.GetHosts(s...)
	}
}

//Combine two string slice and remove duplicate
func concatenateUnique(slice1 []string, slice2 []string) []string {
	elements := append(slice1, slice2...)
	encountered := map[string]bool{}
	// Create a map of all unique elements.
	for v := range elements {
		encountered[elements[v]] = true
	}
	// Place all keys from the map into a slice.
	result := []string{}
	for key, _ := range encountered {
		result = append(result, key)
	}
	return result
}

//groupByMultiFilter => group by multi but filter on service name ( use to get containers with no service name and threat them as standalone containers)
func groupByMultiFilter(filter string, label string, sep string, in interface{}) (map[string][]interface{}, error) {
	m := make(map[string][]interface{})

	if in == nil {
		return m, fmt.Errorf("(groupByMultiFilter) input is nil")
	}

	switch typed := in.(type) {
	case []Service:
		for _, s := range typed {
			value, ok := s.Labels[label]
			if ok && len(value) > 0 && s.Name == filter {
				items := strings.Split(string(value), sep)
				for _, item := range items {
					m[item] = append(m[item], s)
				}
			}
		}
	case []Container:
		for _, c := range typed {
			value, ok := c.Labels[label]
			if ok && len(value) > 0 && c.Service == filter {
				items := strings.Split(string(value), sep)
				for _, item := range items {
					m[item] = append(m[item], c)
				}
			}
		}
	case []Host:
		for _, h := range typed {
			value, ok := h.Labels[label]
			if ok && len(value) > 0 {
				items := strings.Split(string(value), sep)
				for _, item := range items {
					m[item] = append(m[item], h)
				}
			}
		}
	default:
		return m, fmt.Errorf("(groupByMultiFilter) invalid input type %T", in)
	}

	return m, nil
}

// return a string with no "_", ",",";" to create a clean name
func formatClean(toclean string) string {
	cleaned := strings.Replace(toclean, "_", "", -1)
	cleaned = strings.Replace(cleaned, ",", "", -1)
	cleaned = strings.Replace(cleaned, ";", "", -1)
	cleaned = strings.Replace(cleaned, " ", "", -1)
	cleaned = strings.Replace(cleaned, ".", "", -1)
	cleaned = strings.Replace(cleaned, "-", "", -1)
	return cleaned
}

//filterHost => filter on Host name ( use to get containers on a specific host name )
func filterHost(filter string, in []Container) ([]Container, error) {
	if filter == string("*") {
		return in, nil
	}
	m := make([]Container, 0)
	if in == nil {
		return m, fmt.Errorf("(filterHost) input is nil")
	}
	for _, c := range in {
		if c.Host.Name == filter {
			m = append(m, c)
		}
	}
	return m, nil
}

//getAllLabelValue => get all the value for a given label
func getAllLabelValue(filter string, label string, sep string, in interface{}) ([]string, error) {
	m := make([]string, 0)

	if in == nil {
		return m, fmt.Errorf("(getAllLabelValue) input is nil")
	}

	switch typed := in.(type) {
	case []Service:
		for _, s := range typed {
			value, ok := s.Labels[label]
			if filter != string("*") {
				if ok && len(value) > 0 && s.Name == filter {
					items := strings.Split(string(value), sep)
					for _, item := range items {
						m = append(m, item)
					}
				}
			} else {
				if ok && len(value) > 0 {
					items := strings.Split(string(value), sep)
					for _, item := range items {
						m = append(m, item)
					}
				}
			}

		}
	case []Container:
		for _, c := range typed {
			value, ok := c.Labels[label]
			if filter != string("*") {
				if ok && len(value) > 0 && c.Service == filter {
					items := strings.Split(string(value), sep)
					for _, item := range items {
						m = append(m, item)
					}
				}
			} else {
				if ok && len(value) > 0 {
					items := strings.Split(string(value), sep)
					for _, item := range items {
						m = append(m, item)
					}
				}
			}
		}
	case []Host:
		for _, h := range typed {
			value, ok := h.Labels[label]
			if ok && len(value) > 0 {
				items := strings.Split(string(value), sep)
				for _, item := range items {
					m = append(m, item)
				}
			}
		}
	default:
		return m, fmt.Errorf("(getAllLabelValue) invalid input type %T", in)
	}

	return m, nil
}

// groupByLabel takes a label key and a slice of services or hosts and returns a map based
// on the values of the label.
//
// The map key is a string representing the label value. The map value is a
// slice of services or hosts that have the corresponding label value.
// Example:
//    {{range $labelValue, $containers := svc.Containers | groupByLabel "foo"}}
func groupByLabel(label string, in interface{}) (map[string][]interface{}, error) {
	m := make(map[string][]interface{})

	if in == nil {
		return m, fmt.Errorf("(groupByLabel) input is nil")
	}

	switch typed := in.(type) {
	case []Service:
		for _, s := range typed {
			value, ok := s.Labels[label]
			if ok && len(value) > 0 {
				m[value] = append(m[value], s)
			}
		}
	case []Container:
		for _, c := range typed {
			value, ok := c.Labels[label]
			if ok && len(value) > 0 {
				m[value] = append(m[value], c)
			}
		}
	case []Host:
		for _, h := range typed {
			value, ok := h.Labels[label]
			if ok && len(value) > 0 {
				m[value] = append(m[value], h)
			}
		}
	default:
		return m, fmt.Errorf("(groupByLabel) invalid input type %T", in)
	}

	return m, nil
}

func whereLabel(funcName string, in interface{}, label string, test func(string, bool) bool) ([]interface{}, error) {
	result := make([]interface{}, 0)
	if in == nil {
		return result, fmt.Errorf("(%s) input is nil", funcName)
	}
	if label == "" {
		return result, fmt.Errorf("(%s) label is empty", funcName)
	}

	switch typed := in.(type) {
	case []Service:
		for _, s := range typed {
			value, ok := s.Labels[label]
			if test(value, ok) {
				result = append(result, s)
			}
		}
	case []Container:
		for _, c := range typed {
			value, ok := c.Labels[label]
			if test(value, ok) {
				result = append(result, c)
			}
		}
	case []Host:
		for _, s := range typed {
			value, ok := s.Labels[label]
			if test(value, ok) {
				result = append(result, s)
			}
		}
	default:
		return result, fmt.Errorf("(%s) invalid input type %T", funcName, in)
	}

	return result, nil
}

// selects services or hosts from the input that have the given label
func whereLabelExists(label string, in interface{}) ([]interface{}, error) {
	return whereLabel("whereLabelExists", in, label, func(_ string, ok bool) bool {
		return ok
	})
}

// selects services or hosts from the input that have the given label and value
func whereLabelEquals(label, labelValue string, in interface{}) ([]interface{}, error) {
	return whereLabel("whereLabelEquals", in, label, func(value string, ok bool) bool {
		return ok && strings.EqualFold(value, labelValue)
	})
}

// selects services or hosts from the input that have the given label whose value matches the regex
func whereLabelMatches(label, pattern string, in interface{}) ([]interface{}, error) {
	rx, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	return whereLabel("whereLabelMatches", in, label, func(value string, ok bool) bool {
		return ok && rx.MatchString(value)
	})
}

func getArrayValues(funcName string, entries interface{}) (*reflect.Value, error) {
	entriesVal := reflect.ValueOf(entries)

	kind := entriesVal.Kind()

	if kind == reflect.Ptr {
		entriesVal = reflect.Indirect(entriesVal)
		kind = entriesVal.Kind()
	}

	switch kind {
	case reflect.Array, reflect.Slice:
		break
	default:
		return nil, fmt.Errorf("Must pass an array or slice to '%v'; received %v; kind %v", funcName, entries, kind)
	}
	return &entriesVal, nil
}

// Generalized where function
func generalizedWhere(funcName string, entries interface{}, key string, test func(interface{}) bool) (interface{}, error) {
	entriesVal, err := getArrayValues(funcName, entries)

	if err != nil {
		return nil, err
	}

	selection := make([]interface{}, 0)
	for i := 0; i < entriesVal.Len(); i++ {
		v := reflect.Indirect(entriesVal.Index(i)).Interface()

		value := deepGet(v, key)
		if test(value) {
			selection = append(selection, v)
		}
	}

	return selection, nil
}

// selects entries based on key
func where(entries interface{}, key string, cmp interface{}) (interface{}, error) {
	return generalizedWhere("where", entries, key, func(value interface{}) bool {
		return reflect.DeepEqual(value, cmp)
	})
}

// detects whether file or path exists
func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// Creates a map from a list of pairs
func dict(values ...interface{}) (map[string]interface{}, error) {
	if len(values)%2 != 0 {
		return nil, fmt.Errorf("invalid dict call")
	}
	dict := make(map[string]interface{}, len(values)/2)
	for i := 0; i < len(values); i += 2 {
		key, ok := values[i].(string)
		if !ok {
			return nil, fmt.Errorf("dict keys must be strings")
		}
		dict[key] = values[i+1]
	}
	return dict, nil
}

// func exists(path string) (bool, error) {
// 	_, err := os.Stat(path)
// 	if err == nil {
// 		return true, nil
// 	}
// 	if os.IsNotExist(err) {
// 		return false, nil
// 	}
// 	return false, err
// }

// func getArrayValues(funcName string, entries interface{}) (*reflect.Value, error) {
// 	entriesVal := reflect.ValueOf(entries)

// 	kind := entriesVal.Kind()

// 	if kind == reflect.Ptr {
// 		entriesVal = reflect.Indirect(entriesVal)
// 		kind = entriesVal.Kind()
// 	}

// 	switch kind {
// 	case reflect.Array, reflect.Slice:
// 		break
// 	default:
// 		return nil, fmt.Errorf("Must pass an array or slice to '%v'; received %v; kind %v", funcName, entries, kind)
// 	}
// 	return &entriesVal, nil
// }

// Generalized groupBy function
func generalizedGroupBy(funcName string, entries interface{}, getValue func(interface{}) (interface{}, error), addEntry func(map[string][]interface{}, interface{}, interface{})) (map[string][]interface{}, error) {
	entriesVal, err := getArrayValues(funcName, entries)

	if err != nil {
		return nil, err
	}

	groups := make(map[string][]interface{})
	for i := 0; i < entriesVal.Len(); i++ {
		v := reflect.Indirect(entriesVal.Index(i)).Interface()
		value, err := getValue(v)
		if err != nil {
			return nil, err
		}
		if value != nil {
			addEntry(groups, value, v)
		}
	}
	return groups, nil
}

func generalizedGroupByKey(funcName string, entries interface{}, key string, addEntry func(map[string][]interface{}, interface{}, interface{})) (map[string][]interface{}, error) {
	getKey := func(v interface{}) (interface{}, error) {
		return deepGet(v, key), nil
	}
	return generalizedGroupBy(funcName, entries, getKey, addEntry)
}

func groupByMulti(label string, sep string, in interface{}) (map[string][]interface{}, error) {
	m := make(map[string][]interface{})

	if in == nil {
		return m, fmt.Errorf("(groupByMulti) input is nil")
	}

	switch typed := in.(type) {
	case []Service:
		for _, s := range typed {
			value, ok := s.Labels[label]
			if ok && len(value) > 0 {
				items := strings.Split(string(value), sep)
				for _, item := range items {
					m[item] = append(m[item], s)
				}
			}
		}
	case []Container:
		for _, c := range typed {
			value, ok := c.Labels[label]
			if ok && len(value) > 0 {
				items := strings.Split(string(value), sep)
				for _, item := range items {
					m[item] = append(m[item], c)
				}
			}
		}
	case []Host:
		for _, h := range typed {
			value, ok := h.Labels[label]
			if ok && len(value) > 0 {
				items := strings.Split(string(value), sep)
				for _, item := range items {
					m[item] = append(m[item], h)
				}
			}
		}
	default:
		return m, fmt.Errorf("(groupByMulti) invalid input type %T", in)
	}

	return m, nil
}

// groupBy groups a generic array or slice by the path property key
func groupBy(entries interface{}, key string) (map[string][]interface{}, error) {
	return generalizedGroupByKey("groupBy", entries, key, func(groups map[string][]interface{}, value interface{}, v interface{}) {
		groups[value.(string)] = append(groups[value.(string)], v)
	})
}

// groupByKeys is the same as groupBy but only returns a list of keys
func groupByKeys(entries interface{}, key string) ([]string, error) {
	keys, err := generalizedGroupByKey("groupByKeys", entries, key, func(groups map[string][]interface{}, value interface{}, v interface{}) {
		groups[value.(string)] = append(groups[value.(string)], v)
	})

	if err != nil {
		return nil, err
	}

	ret := []string{}
	for k := range keys {
		ret = append(ret, k)
	}
	return ret, nil
}

// groupByLabel is the same as groupBy but over a given label
// func groupByLabel(entries interface{}, label string) (map[string][]interface{}, error) {
// 	getLabel := func(v interface{}) (interface{}, error) {
// 		if container, ok := v.(RuntimeContainer); ok {
// 			if value, ok := container.Labels[label]; ok {
// 				return value, nil
// 			}
// 			return nil, nil
// 		}
// 		return nil, fmt.Errorf("Must pass an array or slice of RuntimeContainer to 'groupByLabel'; received %v", v)
// 	}
// 	return generalizedGroupBy("groupByLabel", entries, getLabel, func(groups map[string][]interface{}, value interface{}, v interface{}) {
// 		groups[value.(string)] = append(groups[value.(string)], v)
// 	})
// }

// Generalized where function
// func generalizedWhere(funcName string, entries interface{}, key string, test func(interface{}) bool) (interface{}, error) {
// 	entriesVal, err := getArrayValues(funcName, entries)

// 	if err != nil {
// 		return nil, err
// 	}

// 	selection := make([]interface{}, 0)
// 	for i := 0; i < entriesVal.Len(); i++ {
// 		v := reflect.Indirect(entriesVal.Index(i)).Interface()

// 		value := deepGet(v, key)
// 		if test(value) {
// 			selection = append(selection, v)
// 		}
// 	}

// 	return selection, nil
// }

// selects entries based on key
// func where(entries interface{}, key string, cmp interface{}) (interface{}, error) {
// 	return generalizedWhere("where", entries, key, func(value interface{}) bool {
// 		return reflect.DeepEqual(value, cmp)
// 	})
// }

// selects entries where a key exists
func whereExist(entries interface{}, key string) (interface{}, error) {
	return generalizedWhere("whereExist", entries, key, func(value interface{}) bool {
		return value != nil
	})
}

// selects entries where a key does not exist
func whereNotExist(entries interface{}, key string) (interface{}, error) {
	return generalizedWhere("whereNotExist", entries, key, func(value interface{}) bool {
		return value == nil
	})
}

// selects entries based on key.  Assumes key is delimited and breaks it apart before comparing
func whereAny(entries interface{}, key, sep string, cmp []string) (interface{}, error) {
	return generalizedWhere("whereAny", entries, key, func(value interface{}) bool {
		if value == nil {
			return false
		} else {
			items := strings.Split(value.(string), sep)
			return len(intersect(cmp, items)) > 0
		}
	})
}

// selects entries based on key.  Assumes key is delimited and breaks it apart before comparing
func whereAll(entries interface{}, key, sep string, cmp []string) (interface{}, error) {
	req_count := len(cmp)
	return generalizedWhere("whereAll", entries, key, func(value interface{}) bool {
		if value == nil {
			return false
		} else {
			items := strings.Split(value.(string), sep)
			return len(intersect(cmp, items)) == req_count
		}
	})
}

// generalized whereLabel function
// func generalizedWhereLabel(funcName string, containers Context, label string, test func(string, bool) bool) (Context, error) {
// 	selection := make([]*RuntimeContainer, 0)

// 	for i := 0; i < len(containers); i++ {
// 		container := containers[i]

// 		value, ok := container.Labels[label]
// 		if test(value, ok) {
// 			selection = append(selection, container)
// 		}
// 	}

// 	return selection, nil
// }

// selects containers that have a particular label
// func whereLabelExists(containers Context, label string) (Context, error) {
// 	return generalizedWhereLabel("whereLabelExists", containers, label, func(_ string, ok bool) bool {
// 		return ok
// 	})
// }

// selects containers that have don't have a particular label
// func whereLabelDoesNotExist(containers Context, label string) (Context, error) {
// 	return generalizedWhereLabel("whereLabelDoesNotExist", containers, label, func(_ string, ok bool) bool {
// 		return !ok
// 	})
// }

// // selects containers with a particular label whose value matches a regular expression
// func whereLabelValueMatches(containers Context, label, pattern string) (Context, error) {
// 	rx, err := regexp.Compile(pattern)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return generalizedWhereLabel("whereLabelValueMatches", containers, label, func(value string, ok bool) bool {
// 		return ok && rx.MatchString(value)
// 	})
// }

// hasPrefix returns whether a given string is a prefix of another string
func hasPrefix(prefix, s string) bool {
	return strings.HasPrefix(s, prefix)
}

// hasSuffix returns whether a given string is a suffix of another string
func hasSuffix(suffix, s string) bool {
	return strings.HasSuffix(s, suffix)
}

func keys(input interface{}) (interface{}, error) {
	if input == nil {
		return nil, nil
	}

	val := reflect.ValueOf(input)
	if val.Kind() != reflect.Map {
		return nil, fmt.Errorf("Cannot call keys on a non-map value: %v", input)
	}

	vk := val.MapKeys()
	k := make([]interface{}, val.Len())
	for i := range k {
		k[i] = vk[i].Interface()
	}

	return k, nil
}

func intersect(l1, l2 []string) []string {
	m := make(map[string]bool)
	m2 := make(map[string]bool)
	for _, v := range l2 {
		m2[v] = true
	}
	for _, v := range l1 {
		if m2[v] {
			m[v] = true
		}
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func contains(item map[string]string, key string) bool {
	if _, ok := item[key]; ok {
		return true
	}
	return false
}

// func dict(values ...interface{}) (map[string]interface{}, error) {
// 	if len(values)%2 != 0 {
// 		return nil, errors.New("invalid dict call")
// 	}
// 	dict := make(map[string]interface{}, len(values)/2)
// 	for i := 0; i < len(values); i += 2 {
// 		key, ok := values[i].(string)
// 		if !ok {
// 			return nil, errors.New("dict keys must be strings")
// 		}
// 		dict[key] = values[i+1]
// 	}
// 	return dict, nil
// }

func hashSha1(input string) string {
	h := sha1.New()
	io.WriteString(h, input)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func marshalJson(input interface{}) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if err := enc.Encode(input); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

func unmarshalJson(input string) (interface{}, error) {
	var v interface{}
	if err := json.Unmarshal([]byte(input), &v); err != nil {
		return nil, err
	}
	return v, nil
}

// arrayFirst returns first item in the array or nil if the
// input is nil or empty
func arrayFirst(input interface{}) interface{} {
	if input == nil {
		return nil
	}

	arr := reflect.ValueOf(input)

	if arr.Len() == 0 {
		return nil
	}

	return arr.Index(0).Interface()
}

// arrayLast returns last item in the array
func arrayLast(input interface{}) interface{} {
	arr := reflect.ValueOf(input)
	return arr.Index(arr.Len() - 1).Interface()
}

// arrayClosest find the longest matching substring in values
// that matches input
func arrayClosest(values []string, input string) string {
	best := ""
	for _, v := range values {
		if strings.Contains(input, v) && len(v) > len(best) {
			best = v
		}
	}
	return best
}

// dirList returns a list of files in the specified path
func dirList(path string) ([]string, error) {
	names := []string{}
	files, err := ioutil.ReadDir(path)
	if err != nil {
		log.Printf("Template error: %v", err)
		return names, nil
	}
	for _, f := range files {
		names = append(names, f.Name())
	}
	return names, nil
}

// coalesce returns the first non nil argument
func coalesce(input ...interface{}) interface{} {
	for _, v := range input {
		if v != nil {
			return v
		}
	}
	return nil
}

// trimPrefix returns a string without the prefix, if present
func trimPrefix(prefix, s string) string {
	return strings.TrimPrefix(s, prefix)
}

// trimSuffix returns a string without the suffix, if present
func trimSuffix(suffix, s string) string {
	return strings.TrimSuffix(s, suffix)
}

// trim returns the string without leading or trailing whitespace
func trim(s string) string {
	return strings.TrimSpace(s)
}

// when returns the trueValue when the condition is true and the falseValue otherwise
func when(condition bool, trueValue, falseValue interface{}) interface{} {
	if condition {
		return trueValue
	} else {
		return falseValue
	}
}

// func filterRunning(config Config, containers Context) Context {
// 	if config.IncludeInactive {
// 		return containers
// 	} else {
// 		filteredContainers := Context{}
// 		for _, container := range containers {
// 			if container.State.Running {
// 				filteredContainers = append(filteredContainers, container)
// 			}
// 		}
// 		return filteredContainers
// 	}
// }

// func GenerateFile(config Config, containers Context) bool {
// 	filteredRunningContainers := filterRunning(config, containers)
// 	filteredContainers := Context{}
// 	if config.OnlyPublished {
// 		for _, container := range filteredRunningContainers {
// 			if len(container.PublishedAddresses()) > 0 {
// 				filteredContainers = append(filteredContainers, container)
// 			}
// 		}
// 	} else if config.OnlyExposed {
// 		for _, container := range filteredRunningContainers {
// 			if len(container.Addresses) > 0 {
// 				filteredContainers = append(filteredContainers, container)
// 			}
// 		}
// 	} else {
// 		filteredContainers = filteredRunningContainers
// 	}

// 	contents := executeTemplate(config.Template, filteredContainers)

// 	if !config.KeepBlankLines {
// 		buf := new(bytes.Buffer)
// 		removeBlankLines(bytes.NewReader(contents), buf)
// 		contents = buf.Bytes()
// 	}

// 	if config.Dest != "" {
// 		dest, err := ioutil.TempFile(filepath.Dir(config.Dest), "docker-gen")
// 		defer func() {
// 			dest.Close()
// 			os.Remove(dest.Name())
// 		}()
// 		if err != nil {
// 			log.Fatalf("Cnable to create temp file: %s\n", err)
// 		}

// 		if n, err := dest.Write(contents); n != len(contents) || err != nil {
// 			log.Fatalf("Failed to write to temp file: wrote %d, exp %d, err=%v", n, len(contents), err)
// 		}

// 		oldContents := []byte{}
// 		if fi, err := os.Stat(config.Dest); err == nil {
// 			if err := dest.Chmod(fi.Mode()); err != nil {
// 				log.Fatalf("Unable to chmod temp file: %s\n", err)
// 			}
// 			if err := dest.Chown(int(fi.Sys().(*syscall.Stat_t).Uid), int(fi.Sys().(*syscall.Stat_t).Gid)); err != nil {
// 				log.Fatalf("Unable to chown temp file: %s\n", err)
// 			}
// 			oldContents, err = ioutil.ReadFile(config.Dest)
// 			if err != nil {
// 				log.Fatalf("Unable to compare current file contents: %s: %s\n", config.Dest, err)
// 			}
// 		}

// 		if bytes.Compare(oldContents, contents) != 0 {
// 			err = os.Rename(dest.Name(), config.Dest)
// 			if err != nil {
// 				log.Fatalf("Unable to create dest file %s: %s\n", config.Dest, err)
// 			}
// 			log.Printf("Generated '%s' from %d containers", config.Dest, len(filteredContainers))
// 			return true
// 		}
// 		return false
// 	} else {
// 		os.Stdout.Write(contents)
// 	}
// 	return true
// }

// func executeTemplate(templatePath string, containers Context) []byte {
// 	tmpl, err := newTemplate(filepath.Base(templatePath)).ParseFiles(templatePath)
// 	if err != nil {
// 		log.Fatalf("Unable to parse template: %s", err)
// 	}

// 	buf := new(bytes.Buffer)
// 	err = tmpl.ExecuteTemplate(buf, filepath.Base(templatePath), &containers)
// 	if err != nil {
// 		log.Fatalf("Template error: %s\n", err)
// 	}
// 	return buf.Bytes()
// }
