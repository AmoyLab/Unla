package utils

func GetBool(m map[string]any, key string, defaultValue bool) bool {
	if m == nil {
		return defaultValue
	}
	v, ok := m[key]
	if !ok {
		return defaultValue
	}
	b, ok := v.(bool)
	if !ok {
		return defaultValue
	}
	return b
}

func GetString(m map[string]any, key string, defaultValue string) string {
	if m == nil {
		return defaultValue
	}
	v, ok := m[key]
	if !ok {
		return defaultValue
	}
	s, ok := v.(string)
	if !ok {
		return defaultValue
	}
	return s
}
