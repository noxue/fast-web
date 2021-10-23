use hyper::header::{self, HeaderName, HeaderValue};
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, StatusCode};
use log::{debug, error, info, trace, warn};
use regex::Regex;
use std::cell::{RefCell, RefMut};
use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::str::FromStr;
use std::sync::Arc;
use std::{convert::Infallible, net::SocketAddr};
use url::form_urlencoded;
use urlencoding::decode;

/// 自定义处理函数的参数类型
pub type Ctx<'a> = RefMut<'a, Context>;

/// json类型的值
pub type Json = serde_json::Value;

/// 用于把json字符串转json对象值
pub use serde_json::json;

/// 用于序列化
pub use serde::Deserialize;

/// 用于反序列化
pub use serde::Serialize;

/// 请求处理函数
type Handler = dyn Fn(&mut Ctx) + 'static + Send + Sync;

/// Http 请求类型
#[derive(Debug, PartialEq, Eq)]
pub enum Method {
    TRACE,
    HEAD,
    GET,
    POST,
    PUT,
    PATCH,
    DELETE,
    OPTIONS,
    ANY,
}

impl From<Method> for String {
    fn from(v: Method) -> Self {
        format!("{:?}", v)
    }
}

impl From<&str> for Method {
    fn from(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "TRACE" => Self::TRACE,
            "HEAD" => Self::HEAD,
            "GET" => Self::GET,
            "POST" => Self::POST,
            "PUT" => Self::PUT,
            "PATCH" => Self::PATCH,
            "DELETE" => Self::DELETE,
            "OPTIONS" => Self::OPTIONS,
            "ANY" => Self::ANY,
            v => panic!("不存在这个类型:{}", v),
        }
    }
}

/// 包含了每次请求的所有信息以及用户自定义信息
#[derive(Default)]
pub struct Context {
    headers: HashMap<String, String>,
    params: HashMap<String, String>,
    queries: HashMap<String, String>,

    // form表单提交的数据
    forms: HashMap<String, String>,

    // 保存自定义信息
    datas: HashMap<String, String>,

    response: Response<Body>,

    // 记录是否处理完毕，根据这个值判断是否还继续往后调用处理函数
    // 最终也根据这个值决定是否返回404，如果为false则返回404
    // 在 context.string() 等函数中 需要把这个值设置为 ture
    is_finished: bool,

    // 用于决定是否跳过剩下的前置过滤器
    is_skip_before_filters: bool,

    // 用于决定是否跳过剩下的后置过滤器
    is_skip_after_filters: bool,

    // 客户端ip和端口
    ip: String,
}

impl Context {
    /// 获取路由规则中的命名参数值
    pub fn param<T>(&self, name: &str) -> Option<T>
    where
        T: FromStr,
        <T as FromStr>::Err: Debug,
    {
        self.params
            .get(name.into())
            .map(|v| v.as_str().parse().unwrap())
    }

    /// 获取query参数值
    pub fn query<T>(&self, name: &str) -> Option<T>
    where
        T: FromStr,
        <T as FromStr>::Err: Debug,
    {
        self.queries
            .get(name.into())
            .map(|v| v.as_str().parse().unwrap())
    }

    /// 获取请求头中的参数值
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name.to_lowercase().as_str())
            .map(|v| v.as_str().parse().unwrap())
    }

    /// 获取 form 表单提交值
    pub fn form<T>(&self, name: &str) -> Option<T>
    where
        T: FromStr,
        <T as FromStr>::Err: Debug,
    {
        self.forms
            .get(name.into())
            .map(|v| v.as_str().parse().unwrap())
    }

    /// 获取自定义数据，前面的处理器可以传给后面的处理器
    /// 通过 set_data 设置
    pub fn data<T>(&self, name: &str) -> Option<T>
    where
        T: FromStr,
        <T as FromStr>::Err: Debug,
    {
        self.datas
            .get(name.into())
            .map(|v| v.as_str().parse().unwrap())
    }

    /// 获取 header 中的参数值
    pub fn set_data<T>(&mut self, name: &str, data: T)
    where
        T: FromStr + Display,
        <T as FromStr>::Err: Debug,
    {
        if self.datas.contains_key(name) {
            self.datas.remove(name);
        }
        self.datas.insert(name.to_string(), data.to_string());
    }

    /// 返回客户端的ip+端口
    pub fn ip(&self) -> String {
        self.ip.clone()
    }
}

impl Context {
    /// 在前置过滤器中调用才有效，调用后会跳过后面的所有前置过滤器
    pub fn skip_before_filters(&mut self) {
        self.is_skip_before_filters = true;
    }

    /// 判断是否要跳过剩下的前置过滤器
    pub fn is_skip_before_filters(&self) -> bool {
        self.is_skip_before_filters
    }

    /// 调用后会跳过后面的所有后置过滤器，在请求处理函数和后置过滤器中调用才有效
    pub fn skip_after_filters(&mut self) {
        self.is_skip_after_filters = true;
    }

    /// 判断是否要跳过剩下的后置过滤器
    pub fn is_skip_after_filters(&self) -> bool {
        self.is_skip_after_filters
    }

    /// 是否处理完毕
    pub fn is_finished(&self) -> bool {
        self.is_finished
    }
}

impl Context {
    /// 临时跳转到指定路径，307跳转
    pub fn redirect(&mut self, url: &str) {
        self.set_header(header::LOCATION.as_str(), url);
        *self.response.status_mut() = StatusCode::TEMPORARY_REDIRECT;
        self.is_finished = true;
    }

    /// 永久跳转到指定的路径，301跳转
    pub fn redirect_301(&mut self, url: &str) {
        self.set_header(header::LOCATION.as_str(), url);
        *self.response.status_mut() = StatusCode::PERMANENT_REDIRECT;
        self.is_finished = true;
    }

    /// 设置响应头信息
    pub fn set_header(&mut self, name: &str, value: &str) {
        let headers = self.response.headers_mut();
        headers.insert(
            HeaderName::from_str(name).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }

    /// 返回html格式字符串
    pub fn string(&mut self, data: &str) {
        self.string_raw(data, "text/html; charset=utf-8");
    }

    /// 返回纯文本格式字符串，不会解析html标签
    pub fn text(&mut self, data: &str) {
        self.string_raw(data, "text/plain; charset=utf-8");
    }

    // 所有输出字符串函数都调用这个函数
    // 这样就不会忘记设置 is_finished 属性了
    #[inline]
    fn string_raw(&mut self, data: &str, content_type: &str) {
        // 注意：必须设置，表示已经设置了返回内容，处理完毕
        self.is_finished = true;
        self.set_header(header::CONTENT_TYPE.as_str(), content_type);
        *self.response.body_mut() = Body::from(data.to_string());
    }

    /// 返回json格式数据
    /// 调用格式
    ///```
    /// c.json(json!({"name":"admin","age":18}));
    /// ```
    /// 如果实现了 `Serialize` Trait 的话可以用下面的方式调用
    ///
    /// ```
    /// let p = Person{name:"admin", age:18};
    /// c.json(&p);
    /// ```
    ///
    pub fn json<T>(&mut self, json: T)
    where
        T: Serialize,
    {
        let data = serde_json::to_string(&json).unwrap();
        self.string_raw(data.as_str(), "application/json; charset=utf-8");
    }
}

/// 路由
#[derive(Default, Debug)]
pub struct Router {
    // 请求处理之前的过滤器
    before_fileters: Vec<Route>,

    // 处理请求的函数
    routes: Vec<Route>,

    // 处理之后的过滤器
    after_fileters: Vec<Route>,

    // 是否忽略路径后面的斜线，默认忽略
    has_slash: bool,
}

impl Router {
    async fn shutdown_signal() {
        tokio::signal::ctrl_c()
            .await
            .expect("安装 CTRL+C 处理器失败");
    }

    /// 静态资源目录
    pub fn static_dir(path: &str, dir: &str) {}

    /// 静态文件
    pub fn static_file(uri: &str, filepath: &str) {}

    async fn handle(
        router: Arc<Router>,
        addr: SocketAddr,
        req: Request<Body>,
    ) -> Result<Response<Body>, Infallible> {
        let routes = router.match_route(req.method().as_str().into(), req.uri().path());

        // 没找到，返回 404
        if routes.is_none() {
            let response = Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                .body(Body::from("没匹配到路由"))
                .unwrap();
            return Ok(response);
        }

        trace!("匹配到的路由：{:?}", routes);

        // 如果匹配成功，从路由中提取参数的值，保存到context中
        let r = routes.unwrap();

        // 每次请求到来就生成一个context,
        // 他包含着请求信息，传递给每个处理函数处理之后
        // 把结果保存在Context中，最后返回给客户端
        let mut context = Context::default();

        // 保存客户端ip和端口
        context.ip = format!("{}:{}", addr.ip(), addr.port());

        // 地址中匹配到的命名参数数据
        let mut tm = HashMap::new();
        for (k, v) in r.params.as_ref().unwrap() {
            tm.insert(k.to_string(), v.to_string());
        }
        context.params = tm;

        // query参数,分割解码保存到context的queries里面
        let qs = req.uri().query();

        if let Some(qs) = qs {
            let queries = form_urlencoded::parse(qs.as_ref())
                .into_owned()
                .collect::<HashMap<String, String>>();

            context.queries = queries;
        }

        // 保存请求头信息
        for (k, v) in req.headers() {
            context.headers.insert(
                k.to_string().to_lowercase(),
                v.to_str().unwrap_or_default().to_string(),
            );
        }

        // 优先处理 form-data 类型数据

        // debug!("headers:{:#?}", context.headers);
        
        // 处理body中的内容
        if let Ok(body) = hyper::body::to_bytes(req).await {
            let form = form_urlencoded::parse(body.as_ref())
                .into_owned()
                .collect::<HashMap<String, String>>();

            debug!("body的数据:{:?}", form);

            context.forms = form;
        }

        // 根据请求类型，把数据放到对应的地方
        let context = RefCell::new(context);

        // 前置过滤器
        for r in r.before {
            // 获取Context的可变引用，用于修改Context中的内容
            let mut context1 = context.borrow_mut();

            // 如果跳过前置过滤器，就不执行后面的过滤器了
            if context1.is_skip_before_filters || context1.is_finished() {
                break;
            }

            // 调用过滤器函数
            (r.handler)(&mut context1);
        }

        // 控制器函数
        if let Some(r) = r.route {
            // trace!("匹配成功:{}", req.uri().path());
            trace!("路由规则:{:?}", r);

            let mut context1 = context.borrow_mut();

            // 前置处理器没有直接返回，才调用这个处理器
            if !context1.is_finished() {
                (r.handler)(&mut context1);
            }
        }

        // 后置过滤器
        for r in r.after {
            let mut context1 = context.borrow_mut();

            // 如果跳过后置过滤器，就不执行后面的过滤器了
            if context1.is_finished() || context1.is_skip_after_filters {
                break;
            }

            // 调用过滤器函数
            (r.handler)(&mut context1);
        }

        // let context1 = context.borrow_mut();

        if context.borrow_mut().is_finished() {
            Ok(Response::from(context.take().response))
        } else {
            let response = Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                .body(Body::from("没匹配到处理函数"))
                .unwrap();
            Ok(response)
        }
    }

    /// 启动服务器
    /// ```rust
    /// use fast_router::router::Router;
    ///
    /// fn main(){
    ///     let mut r = Router::new();
    ///     r.get("",|c|c.string("hello world"));
    ///     r.run("127.0.0.1:80");
    /// }
    /// ```
    pub fn run(self, host: &str) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let addr = match SocketAddr::from_str(host) {
                Ok(v) => v,
                Err(_) => {
                    error!("解析地址失败，请确认格式为(ip:port),你的地址是:{}", host);
                    return;
                }
            };

            // 路由表信息
            let router: Arc<Router> = Arc::new(self);

            debug!("路由表：{:#?}", router.clone());

            // 创建service处理每个请求
            let make_service = make_service_fn(move |conn: &AddrStream| {
                // 客户端地址信息
                let addr = conn.remote_addr();

                // 每个请求都克隆一个路由信息，传入给处理函数
                let router = router.clone();
                let service = service_fn(move |req| Self::handle(router.clone(), addr, req));
                async move { Ok::<_, Infallible>(service) }
            });
            let server = Server::bind(&addr).serve(make_service);

            let graceful = server.with_graceful_shutdown(Self::shutdown_signal());

            info!("启动成功: {}", host);

            if let Err(e) = graceful.await {
                eprintln!("server error: {}", e);
            }
        });
    }

    /// 启动tls服务器
    pub fn run_tls(host: &str, pem: &str, key: &str) {}
}

impl Router {
    /// 创建一个默认的Router
    pub fn new() -> Self {
        Self::default()
    }

    /// 路由分组
    pub fn group(&mut self, path: &str) -> RouterGroup {
        RouterGroup::new(path, self)
    }

    /// 区分路径最后的斜线，默认不区分
    pub fn has_slash(&mut self) {
        self.has_slash = true;
    }

    /// 根据用户请求地址，匹配路由
    /// 并从请求地址中提取命名路由对应的数据
    fn match_route(&self, method: Method, path: &str) -> Option<MatchedRoute> {
        // 如果忽略地址最后的斜线，并且长度不是0，就去掉后面的斜线
        let path = if !self.has_slash && path.len() > 0 && &path[path.len() - 1..] == "/" {
            &path[..path.len() - 1]
        } else {
            path
        };

        // 保存从请求路径中提交的键值对
        // 比如:
        //      路由：      /user/:name
        //      请求地址：  /user/admin
        // 则保存的是 name=>admin 这样的键值对
        let mut params: HashMap<String, String> = HashMap::new();

        trace!("查找路由:{}", path);
        // 寻找匹配的路由
        let mut matched_route = None;
        for route in &self.routes {
            if (method == route.method || route.method == Method::ANY) && route.re.is_match(path) {
                // 找到匹配的路由
                matched_route = Some(route);

                // 提取参数
                let cps = route.re.captures(path).unwrap();
                trace!("参数列表：{:?}", route.param_names);
                for name in &route.param_names {
                    // urldecode解码
                    match decode(cps.name(name.as_str()).unwrap().as_str()) {
                        Ok(value) => {
                            params.insert(name.to_string(), value.to_string());
                        }
                        Err(e) => {
                            warn!("路由参数值urldecode解码出错：{:?}", e)
                        }
                    }
                }

                break;
            }
        }

        // 寻找前置过滤器
        let mut before_filters = vec![];
        for route in &self.before_fileters {
            if (method == route.method || route.method == Method::ANY) && route.re.is_match(path) {
                // 找到匹配的过滤器，可能会有多个
                before_filters.push(route);

                // 提取参数
                let cps = route.re.captures(path).unwrap();
                trace!("参数列表：{:?}", route.param_names);
                for name in &route.param_names {
                    match decode(cps.name(name.as_str()).unwrap().as_str()) {
                        Ok(value) => {
                            params.insert(name.to_string(), value.to_string());
                        }
                        Err(e) => {
                            warn!("路由参数值urldecode解码出错：{:?}", e)
                        }
                    }
                }
            }
        }

        // 输出所有参数值
        trace!("路径中的参数值：{:?}", params);

        // 寻找后置过滤器
        let mut after_filters = vec![];
        for route in &self.after_fileters {
            if (method == route.method || route.method == Method::ANY) && route.re.is_match(path) {
                // 找到匹配的过滤器，可能会有多个
                after_filters.push(route);
            }
        }

        // 如果都没找到
        if matched_route.is_none() && before_filters.len() == 0 && after_filters.len() == 0 {
            return None;
        }

        Some(MatchedRoute {
            before: before_filters,
            route: matched_route,
            after: after_filters,
            params: Some(params),
        })
    }
}

impl Router {
    fn add<F>(&mut self, method: Method, path: &str, handler: F)
    where
        F: Fn(&mut Ctx) + 'static + Send + Sync,
    {
        // assert!(path.len() > 0);

        let route = Route::new(
            method,
            path.to_owned(),
            Box::new(handler),
            None,
            self.has_slash,
        );

        self.routes.push(route);
    }

    /// 添加前置中间件
    pub fn before<F>(&mut self, method: Method, path: &str, handler: F)
    where
        F: Fn(&mut Ctx) + 'static + Send + Sync,
    {
        let route = Route::new_filter(
            method,
            path.to_owned(),
            Box::new(handler),
            None,
            self.has_slash,
        );

        self.before_fileters.push(route);
    }

    /// 添加后置中间件
    pub fn after<F>(&mut self, method: Method, path: &str, handler: F)
    where
        F: Fn(&mut Ctx) + 'static + Send + Sync,
    {
        let route = Route::new_filter(
            method,
            path.to_owned(),
            Box::new(handler),
            None,
            self.has_slash,
        );

        self.after_fileters.push(route);
    }

    /// 封装各类请求
    pub fn get<F>(&mut self, path: &str, handler: F)
    where
        F: Fn(&mut Ctx) + 'static + Send + Sync,
    {
        self.add(Method::GET, path, handler);
    }

    pub fn post<F>(&mut self, path: &str, handler: F)
    where
        F: Fn(&mut Ctx) + 'static + Send + Sync,
    {
        self.add(Method::POST, path, handler);
    }

    pub fn trace<F>(&mut self, path: &str, handler: F)
    where
        F: Fn(&mut Ctx) + 'static + Send + Sync,
    {
        self.add(Method::TRACE, path, handler);
    }

    pub fn head<F>(&mut self, path: &str, handler: F)
    where
        F: Fn(&mut Ctx) + 'static + Send + Sync,
    {
        self.add(Method::HEAD, path, handler);
    }

    pub fn put<F>(&mut self, path: &str, handler: F)
    where
        F: Fn(&mut Ctx) + 'static + Send + Sync,
    {
        self.add(Method::PUT, path, handler);
    }

    pub fn patch<F>(&mut self, path: &str, handler: F)
    where
        F: Fn(&mut Ctx) + 'static + Send + Sync,
    {
        self.add(Method::PATCH, path, handler);
    }

    pub fn delete<F>(&mut self, path: &str, handler: F)
    where
        F: Fn(&mut Ctx) + 'static + Send + Sync,
    {
        self.add(Method::DELETE, path, handler);
    }

    pub fn options<F>(&mut self, path: &str, handler: F)
    where
        F: Fn(&mut Ctx) + 'static + Send + Sync,
    {
        self.add(Method::OPTIONS, path, handler);
    }

    pub fn any<F>(&mut self, path: &str, handler: F)
    where
        F: Fn(&mut Ctx) + 'static + Send + Sync,
    {
        self.add(Method::ANY, path, handler);
    }
}

/// 根据地址匹配到的路由
#[derive(Debug)]
struct MatchedRoute<'a> {
    before: Vec<&'a Route>,
    route: Option<&'a Route>,
    after: Vec<&'a Route>,
    // 地址参数
    params: Option<HashMap<String, String>>,
}

/// 路由组，拥有和`Router`类似的方法
pub struct RouterGroup<'a> {
    path: String,
    router: &'a mut Router,
}

impl<'a> RouterGroup<'a> {
    fn new(path: &str, router: &'a mut Router) -> Self {
        Self {
            path: path.to_string(),
            router: router,
        }
    }

    /// 处理两个地址相加，防止地址相加出现两个斜线或没有斜线
    fn concat_path(path1: &str, path2: &str) -> String {
        // 两个路径除去斜杠之后的长度
        let l1 = path1.replace("/", "").len();
        let l2 = path2.replace("/", "").len();

        if l1 == 0 && l2 > 0 {
            // 如果前面的地址为空，返回第二个地址
            return path2.to_string();
        } else if l2 == 0 && l1 > 0 {
            // 如果后面的地址为空，返回第一个
            return path1.to_string();
        } else if l1 == 0 && l2 == 0 {
            return "".to_string();
        }

        match (&path1[path1.len() - 1..], &path2[0..1]) {
            // 两个斜线就去掉一个
            ("/", "/") => path1.to_string() + &path2[1..],

            // 没有斜线就添加一个
            (p1, p2) if p1 != "/" && p2 != "/" => path1.to_string() + "/" + path2,

            // 一个斜线就直接连起来
            _ => path1.to_string() + path2,
        }
    }

    fn add<F>(&mut self, method: Method, path: &str, handler: F)
    where
        F: Fn(&mut Ctx) + 'static + Send + Sync,
    {
        let path = Self::concat_path(self.path.as_str(), path);

        self.router.add(method, path.as_str(), Box::new(handler));
    }

    /// 生成一个分组
    pub fn group(&mut self, path: &str) -> RouterGroup {
        let path = Self::concat_path(self.path.as_str(), path);
        RouterGroup::new(path.as_str(), self.router)
    }

    /// 添加前置处理器
    pub fn before<F>(&mut self, method: Method, path: &str, handler: F)
    where
        F: Fn(&mut Ctx) + 'static + Send + Sync,
    {
        let path = Self::concat_path(self.path.as_str(), path);

        self.router.before(method, path.as_str(), handler);
    }

    /// 添加后置处理器
    pub fn after<F>(&mut self, method: Method, path: &str, handler: F)
    where
        F: Fn(&mut Ctx) + 'static + Send + Sync,
    {
        let path = Self::concat_path(self.path.as_str(), path);

        self.router.after(method, path.as_str(), handler);
    }

    /// 封装各类请求
    pub fn get<F>(&mut self, path: &str, handler: F)
    where
        F: Fn(&mut Ctx) + 'static + Send + Sync,
    {
        self.add(Method::GET, path, handler);
    }

    pub fn post<F>(&mut self, path: &str, handler: F)
    where
        F: Fn(&mut Ctx) + 'static + Send + Sync,
    {
        self.add(Method::POST, path, handler);
    }

    pub fn trace<F>(&mut self, path: &str, handler: F)
    where
        F: Fn(&mut Ctx) + 'static + Send + Sync,
    {
        self.add(Method::TRACE, path, handler);
    }

    pub fn head<F>(&mut self, path: &str, handler: F)
    where
        F: Fn(&mut Ctx) + 'static + Send + Sync,
    {
        self.add(Method::HEAD, path, handler);
    }

    pub fn put<F>(&mut self, path: &str, handler: F)
    where
        F: Fn(&mut Ctx) + 'static + Send + Sync,
    {
        self.add(Method::PUT, path, handler);
    }

    pub fn patch<F>(&mut self, path: &str, handler: F)
    where
        F: Fn(&mut Ctx) + 'static + Send + Sync,
    {
        self.add(Method::PATCH, path, handler);
    }

    pub fn delete<F>(&mut self, path: &str, handler: F)
    where
        F: Fn(&mut Ctx) + 'static + Send + Sync,
    {
        self.add(Method::DELETE, path, handler);
    }

    pub fn options<F>(&mut self, path: &str, handler: F)
    where
        F: Fn(&mut Ctx) + 'static + Send + Sync,
    {
        self.add(Method::OPTIONS, path, handler);
    }

    pub fn any<F>(&mut self, path: &str, handler: F)
    where
        F: Fn(&mut Ctx) + 'static + Send + Sync,
    {
        self.add(Method::ANY, path, handler);
    }
}

/// 路径的一个路由信息
struct Route {
    // 请求方式，不区分大小写
    method: Method,

    // 路由名字，用于生成url
    name: Option<String>,

    // 路由规则
    path: String,

    // 路径编译之后的正则表达式对象
    re: Regex,

    // 处理函数
    handler: Box<Handler>,

    // 是否保留路径最后的斜线
    has_slash: bool,

    // 路径中的分组命名
    param_names: Vec<String>,
}

impl Debug for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Route")
            .field("method", &self.method)
            .field("name", &self.name)
            .field("path", &self.path)
            .field("re", &self.re)
            .field("has_slash", &self.has_slash)
            .field("param_names", &self.param_names)
            .finish()
    }
}

impl Route {
    /// 创建路由
    fn new(
        method: Method,
        path: String,
        handler: Box<Handler>,
        name: Option<String>,
        has_slash: bool,
    ) -> Self {
        Self::build(method, path, handler, name, has_slash, false)
    }

    /// 创建过滤器
    fn new_filter(
        method: Method,
        path: String,
        handler: Box<Handler>,
        name: Option<String>,
        has_slash: bool,
    ) -> Self {
        Self::build(method, path, handler, name, has_slash, true)
    }
    fn build(
        method: Method,
        path: String,
        handler: Box<Handler>,
        name: Option<String>,
        has_slash: bool,

        // 是否是过滤器，如果是过滤器，正则结尾不需要$，这样只要匹配一部分路径即可
        is_filter: bool,
    ) -> Self {
        // 如果忽不保留路径最后的斜线，就去掉，否则就不变
        let path = if !has_slash && !path.is_empty() && &path[path.len() - 1..] == "/" {
            path[..path.len() - 1].to_string()
        } else {
            path
        };

        // 把自定义类型的路由转换成 正则路由
        let path = Self::path_param_type_to_regex(path.as_str());

        // 把正则路由转换成 在组名的正则路由
        let path_and_names = Self::path2regex(path.as_str());

        trace!("路由参数列表：{:?}", path_and_names.1);

        let mut re_str = format!("^{}", path_and_names.0);

        // 如果不是过滤器，需要匹配整个地址
        if !is_filter {
            re_str += "$";
        }

        let re = Regex::new(re_str.as_str()).unwrap();
        Self {
            method,
            path: path.clone(),
            name,
            re,
            handler,
            has_slash,
            param_names: path_and_names.1,
        }
    }

    /// 返回对应类型的正则
    #[inline]
    fn type_to_regex(type_name: &str) -> String {
        // i8|u8|i32|u32|i64|u64|i128|u128|bool
        match type_name {
            "i8" => r"[\-]{0,1}\d{1,3}",
            "i16" => r"[\-]{0,1}\d{1,5}",
            "i32" => r"[\-]{0,1}\d{1,10}",
            "i64" => r"[\-]{0,1}\d{1,19}",
            "i128" => r"[\-]{0,1}\d{1,39}",
            "u8" => r"\d{1,3}",
            "u16" => r"\d{1,5}",
            "u32" => r"\d{1,10}",
            "u64" => r"\d{1,20}",
            "u128" => r"\d{1,39}",
            "bool" => r"true|false",
            v => {
                panic!("路由不支持该参数类型：{}", v);
            }
        }
        .to_string()
    }

    /// 把路由规则转换成正则表达式格式
    ///
    /// 例如：  /user/:id:usize/:page:usize
    /// 转换成：/user/:id:(\d+)/:page:(\d+)
    ///
    /// 返回值说明：
    /// 返回的第一个值是转换后的正则路由，第二个参数是正则路由中的命名参数名字
    /// 比如：/:user/:id  第二个参数就返回["user","id"]
    ///
    #[inline]
    fn path_param_type_to_regex(path: &str) -> String {
        let mut p = String::new();

        let re = Regex::new(r#"^:(?P<name>[a-zA-a_]{1}[a-zA-Z_0-9]*?):(?P<type>i32|u32|i8|u8|i64|u64|i128|u128|bool)$"#).unwrap();

        for node in path.split("/") {
            if node.is_empty() {
                continue;
            }

            if re.is_match(node) {
                let cms = re.captures(node).unwrap();
                let name = cms.name("name").unwrap().as_str();
                let tp = cms.name("type").unwrap().as_str();

                let type_reg = Self::type_to_regex(tp);
                p += format!("/:{}:({})", name, type_reg).as_str();
            } else if &node[0..1] == ":" && &node[node.len() - 1..] != ")" {
                // 如果不匹配，以 : 开头，表示没写类型，默认匹配任意字符串
                // 也就是这种情况 /:name/
                p = p + "/" + node + r#":([\w\-%_\.~:;'"@=+,]+)"#;
            } else {
                // 自定义正则就不改变
                p = p + "/" + node;
            }
        }
        // 最后如果有 / 也要加上
        if path.len() > 0 && &path[path.len() - 1..] == "/" {
            p += "/";
        }

        p
    }

    /// 把正则路由转换成，命名组正则表达式，如果是自定义类型的，需要先调用 path_param_type_to_regex 函数来处理成正则路由
    ///
    /// 例如把 /admin/:name:([^/]+)/:id:(\d+)
    /// 转换成 /admin/(?P<name>[^/]+)/(?P<id>\d+)
    ///
    #[inline]
    fn path2regex(path: &str) -> (String, Vec<String>) {
        let mut p = String::new();

        let re = Regex::new(r#"^:(?P<name>[a-zA-a_]{1}[a-zA-Z_0-9]*?):\((?P<reg>.*)\)$"#).unwrap();

        let mut names = vec![];

        for node in path.split("/") {
            if node.is_empty() {
                continue;
            }

            if re.is_match(node) {
                let cms = re.captures(node).unwrap();
                let name = cms.name("name").unwrap().as_str();
                names.push(name.to_string());

                p += re
                    .replace(node, "/(?P<${name}>${reg})")
                    .to_string()
                    .as_str();
            } else {
                p += "/";
                p += node;
            }
        }
        // 最后如果有 / 也要加上
        if path.len() > 0 && &path[path.len() - 1..] == "/" {
            p += "/";
        }

        (p, names)
    }
}

#[cfg(test)]
mod tests {

    use std::cell::RefCell;
    use std::cell::RefMut;
    use std::str::FromStr;

    use regex::Regex;

    use crate::router::Route;

    use super::Method;
    use super::Router;
    use super::RouterGroup;

    #[test]
    fn test_concat() {
        assert_eq!("a/b".to_string(), RouterGroup::concat_path("a/", "/b"));
        assert_eq!("a/b".to_string(), RouterGroup::concat_path("a", "/b"));
        assert_eq!("a/b".to_string(), RouterGroup::concat_path("a/", "b"));
        assert_eq!("a/b".to_string(), RouterGroup::concat_path("a", "b"));
        assert_eq!("a".to_string(), RouterGroup::concat_path("a", ""));
        assert_eq!("".to_string(), RouterGroup::concat_path("", ""));
        assert_eq!("b".to_string(), RouterGroup::concat_path("", "b"));
    }

    #[test]
    fn test_router() {
        // let mut r = Router::default();
        // r.has_slash();

        // r.post("/:user/:id", |c| {});

        // let mut g = r.group("/:v1");
        // {
        //     g.get("admin/:name:i32", |mut c| {});
        //     g.post("/admin/u32/", |c| {});

        //     let mut g1 = g.group("/test1");
        //     {
        //         g1.put("admin/login/", |c| {});
        //         g1.delete("/admin/login1/", |c| {});
        //     }
        // }

        // let mut g = r.group("/a1/");
        // {
        //     g.add(Method::GET, "/admin/login", |c| {});
        //     g.add(Method::DELETE, "/admin/login1", |c| {});

        //     let mut g1 = g.group("/test1/");
        //     {
        //         g1.add(Method::OPTIONS, "/admin/login", |c| {});
        //         g1.add(Method::ANY, "/admin/login1", |c| {});
        //     }
        // }

        // for v in r.routes {
        //     println!("{:?}", v);
        // }
    }

    #[test]
    fn test_router1() {
        let mut r = Router::default();

        let mut g = r.group("/a1/");
        {
            let s = "aa".to_string();
            g.add(Method::GET, "/admin/login", move |c| {
                let t = &s;
            });
            g.add(Method::DELETE, "/admin/login1", |c| {});

            let mut g1 = g.group("/test1/");
            {
                g1.add(Method::OPTIONS, "/admin/login", |c| {});
                g1.add(Method::ANY, "/admin/login1", |c| {});
            }
        }

        for v in r.routes {
            println!("{:?}", v);
        }
    }
    #[test]
    fn test_regex() {
        let re = Regex::new(r"^/user/(?P<name>\w+)/(?P<id>\d{1,10})$").unwrap();

        let v = re.captures("/user/zhangsan/123").unwrap();
        let r = v.name("name").unwrap();
        println!("{:?}", r.as_str());
        let r = v.name("id").unwrap();
        println!("{:?}", r.as_str());
    }

    #[test]
    fn test_path2regex() {
        /*
        把     /admin/:name:([^/]+)/:id:(\d+)
            转换成 /admin/(?P<name>[^/]+)/(?P<id>\d+)
        */

        let s = r#"/admin/:name:(.*+?)/info/:id:(\d+?)/name/"#;
        let p = Route::path2regex(s);

        assert_eq!(
            r"/admin/(?P<name>.*+?)/info/(?P<id>\d+?)/name/",
            p.0.as_str()
        );
    }

    #[test]
    fn test_path_param_to_regex() {
        let path = "/user/:id:(.*)/:page:u32";
        let p = Route::path_param_type_to_regex(path);
        assert_eq!(r"/user/:id:(.*)/:page:(\d{1,10})", p.as_str());
    }

    #[test]
    fn test_router_match() {
        // let mut r = Router::default();

        // let mut g = r.group("/v1");
        // {
        //     g.before(Method::ANY, "admin/:name", |c| {});
        //     g.after(Method::ANY, "admin/:name", |c| {});

        //     g.any("admin/:name:i32", |c| {});
        //     g.any("admin/:name", |c| {});
        //     g.any("admin/:name/:id:u32", |c| {});
        //     g.post("/admin/login1/", |c| {});
        // }

        // let route = r.match_route(Method::GET, "/v1/admin/zhang山/23423");

        // // (route.as_ref().unwrap().route.unwrap().handler)("xxx".to_string());
    }

    #[test]
    fn test_filters() {}

    #[test]
    fn test_fnonce() {
        struct Context {
            data: String,
        }

        type Ctx<'a> = RefMut<'a, Context>;
        type Hander = dyn Fn(Ctx) + 'static;

        struct Route {
            handler: Box<Hander>,
        }

        fn get<F>(f: F)
        where
            F: Fn(Ctx) + 'static,
        {
            let r = &Route {
                handler: Box::new(f),
            };

            let c = RefCell::new(Context {
                data: "".to_string(),
            });
            let v = c.borrow_mut();
            (r.handler)(v);
            let v = c.borrow_mut();
            (r.handler)(v);
        }

        let s = String::new();
        // let ctx = Context{data:"sss".to_string()};
        get(move |mut c| {
            let v = &s;
            c.data = "xxx".to_string();
        });
    }
}
