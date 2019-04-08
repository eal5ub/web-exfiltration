package main

type Message map[string]interface{}

func (p Message) Int(k string) int {
	if c, ok := p[k].(int); ok {
		return c
	}
	if c, ok := p[k].(float64); ok {
		return int(c)
	}
	return 0
}

func (p Message) Bool(k string) bool {
	if c, ok := p[k].(bool); ok {
		return c
	}
	return false
}

func (p Message) String(k string) string {
	if v, ok := p[k].(string); ok {
		return v
	}
	return ""
}

func (p Message) Strings(k string) []string {
	v, ok := p[k]
	if !ok {
		return nil
	}
	xv := v.([]interface{})
	sv := []string{}
	for _, x := range xv {
		sv = append(sv, x.(string))
	}
	return sv
}

func (p Message) Message(k string) Message {
	v, ok := p[k]
	if !ok {
		return nil
	}
	return Message(v.(map[string]interface{}))
}

func (p Message) Messages(k string) []Message {
	v, ok := p[k]
	if !ok {
		return nil
	}
	xv := v.([]interface{})
	mv := []Message{}
	for _, x := range xv {
		mv = append(mv, Message(x.(map[string]interface{})))
	}
	return mv
}
