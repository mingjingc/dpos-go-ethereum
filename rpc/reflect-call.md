
反射调用函数：
```go
func hello(s string) {
	fmt.Println(s)
}

func main() {
	fn := reflect.ValueOf(hello)
	fn.Call([]reflect.Value{reflect.ValueOf("你好哈")})
}
```

反射调用对象函数
```go
type People struct {
}
// 反射调用，方法需要大写
func (p *People) Say(s string) {
	fmt.Println(s)
}

func main() {
	var o interface{} = &People{}
	v := reflect.ValueOf(o)
	m := v.MethodByName("Say") // 方法名需要大写
	m.Call([]reflect.Value{reflect.ValueOf("成功了")})

	// Geth 使用另一种调用
	var o interface{} = &People{}
	v := reflect.ValueOf(o).Type()

	for m := 0; m < v.NumMethod(); m++ {
		method := v.Method(m)
		// 下面语句打印结果： {Say  func(*main.People, string) <func(*main.People, string) Value> 0}
		fmt.Println(method)
		method.Func.Call([]reflect.Value{reflect.ValueOf(&People{}), reflect.ValueOf("你好哈")})
	}
}

// callback 中的 fn 元素是 reflect.Method，调用时需要传入对象和参数
type service struct {
	name          string               // name for service
	callbacks     map[string]*callback // registered handlers
	subscriptions map[string]*callback // available subscriptions/notifications
}

```
