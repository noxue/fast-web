use std::{collections::HashMap, vec};

use regex::Regex;

/// 包含了请求的所有信息以及用户自定义信息
type Context = String;

/// 请求处理函数
type Handler = fn(Context);

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
    pub fn group(&mut self, path: &str) -> RouterGroup {
        RouterGroup::new(path, self)
    }
    fn add(&mut self, method: Method, path: &str, handler: Handler) {
        // assert!(path.len() > 0);

        let route = Route::new(method, path.to_owned(), handler, None, self.has_slash);

        self.routes.push(route);
    }

    /// 区分路径最后的斜线，默认不区分
    pub fn has_slash(&mut self) {
        self.has_slash = true;
    }

    /// 根据用户请求地址，匹配路由
    fn match_route(&self, method: Method, path: &str) -> Option<MatchedRoute> {

        // 如果忽略地址最后的斜线，并且长度不是0，就去掉后面的斜线
        let path = if !self.has_slash && path.len() > 0 && &path[path.len() - 1..] == "/" {
            &path[..path.len() - 1]
        } else {
            path
        };

        // 寻找匹配的路由
        let mut matched_route = None;
        for route in &self.routes {
            println!("{:?}", route);
            if (method == route.method || route.method == Method::ANY) && route.re.is_match(path) {
                // 找到匹配的路由
                matched_route = Some(route);
                break;
            }
        }

        // 寻找前置过滤器
        let mut before_filters = vec![];
        for route in &self.before_fileters {
            if (method == route.method || route.method == Method::ANY) && route.re.is_match(path) {
                // 找到匹配的过滤器，可能会有多个
                before_filters.push(route);
            }
        }

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
        })
    }

    /// 添加前置中间件
    pub fn before(&mut self, method: Method, path: &str, handler: Handler) {
        let route = Route::new_filter(method, path.to_owned(), handler, None, self.has_slash);

        self.before_fileters.push(route);
    }

    /// 添加后置中间件
    pub fn after(&mut self, method: Method, path: &str, handler: Handler) {
        let route = Route::new_filter(method, path.to_owned(), handler, None, self.has_slash);

        self.after_fileters.push(route);
    }

    /// 封装各类请求
    pub fn get(&mut self, path: &str, handler: Handler) {
        self.add(Method::GET, path, handler);
    }

    pub fn post(&mut self, path: &str, handler: Handler) {
        self.add(Method::POST, path, handler);
    }

    pub fn trace(&mut self, path: &str, handler: Handler) {
        self.add(Method::TRACE, path, handler);
    }

    pub fn head(&mut self, path: &str, handler: Handler) {
        self.add(Method::HEAD, path, handler);
    }

    pub fn put(&mut self, path: &str, handler: Handler) {
        self.add(Method::PUT, path, handler);
    }

    pub fn patch(&mut self, path: &str, handler: Handler) {
        self.add(Method::PATCH, path, handler);
    }

    pub fn delete(&mut self, path: &str, handler: Handler) {
        self.add(Method::DELETE, path, handler);
    }

    pub fn options(&mut self, path: &str, handler: Handler) {
        self.add(Method::OPTIONS, path, handler);
    }

    pub fn any(&mut self, path: &str, handler: Handler) {
        self.add(Method::ANY, path, handler);
    }
}

/// 根据地址匹配到的路由
#[derive(Debug)]
struct MatchedRoute<'a> {
    before: Vec<&'a Route>,
    route: Option<&'a Route>,
    after: Vec<&'a Route>,
}

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

    fn add(&mut self, method: Method, path: &str, handler: Handler) {
        let path = Self::concat_path(self.path.as_str(), path);

        self.router.add(method, path.as_str(), handler);
    }

    /// 生成一个分组
    pub fn group(&mut self, path: &str) -> RouterGroup {
        let path = Self::concat_path(self.path.as_str(), path);
        RouterGroup::new(path.as_str(), self.router)
    }

    /// 添加前置处理器
    pub fn before(&mut self, method: Method, path: &str, handler: Handler) {
        let path = Self::concat_path(self.path.as_str(), path);

        self.router.before(method, path.as_str(), handler);
    }

    /// 添加后置处理器
    pub fn after(&mut self, method: Method, path: &str, handler: Handler) {
        let path = Self::concat_path(self.path.as_str(), path);

        self.router.after(method, path.as_str(), handler);
    }

    /// 封装各类请求
    pub fn get(&mut self, path: &str, handler: Handler) {
        self.add(Method::GET, path, handler);
    }

    pub fn post(&mut self, path: &str, handler: Handler) {
        self.add(Method::POST, path, handler);
    }

    pub fn trace(&mut self, path: &str, handler: Handler) {
        self.add(Method::TRACE, path, handler);
    }

    pub fn head(&mut self, path: &str, handler: Handler) {
        self.add(Method::HEAD, path, handler);
    }

    pub fn put(&mut self, path: &str, handler: Handler) {
        self.add(Method::PUT, path, handler);
    }

    pub fn patch(&mut self, path: &str, handler: Handler) {
        self.add(Method::PATCH, path, handler);
    }

    pub fn delete(&mut self, path: &str, handler: Handler) {
        self.add(Method::DELETE, path, handler);
    }

    pub fn options(&mut self, path: &str, handler: Handler) {
        self.add(Method::OPTIONS, path, handler);
    }

    pub fn any(&mut self, path: &str, handler: Handler) {
        self.add(Method::ANY, path, handler);
    }
}

/// 路径的一个路由信息
#[derive(Debug)]
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
    handler: Handler,

    // 是否保留路径最后的斜线
    has_slash: bool,
}

impl Route {
    /// 创建路由
    fn new(
        method: Method,
        path: String,
        handler: Handler,
        name: Option<String>,
        has_slash: bool,
    ) -> Self {
        Self::build(method, path, handler, name, has_slash, false)
    }

    /// 创建过滤器
    fn new_filter(
        method: Method,
        path: String,
        handler: Handler,
        name: Option<String>,
        has_slash: bool,
    ) -> Self {
        Self::build(method, path, handler, name, has_slash, true)
    }
    fn build(
        method: Method,
        path: String,
        handler: Handler,
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
        let re_str = Self::path2regex(path.as_str());

        let mut re_str = format!("^{}", re_str);

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
                println!("name:{}\t type:{}", name, tp);

                let type_reg = Self::type_to_regex(tp);
                p += format!("/:{}:({})", name, type_reg).as_str();
            } else if &node[0..1] == ":" {
                // 如果不匹配，以 : 开头，表示没写类型，默认匹配任意字符串
                p = p + "/" + node + r":(\w+)";
            } else {
                p = p + "/" + node;
            }
        }
        // 最后如果有 / 也要加上
        if &path[path.len() - 1..] == "/" {
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
    fn path2regex(path: &str) -> String {
        let mut p = String::new();

        let re = Regex::new(r#"^:(?P<name>[a-zA-a_]{1}[a-zA-Z_0-9]*?):\((?P<reg>.*)\)$"#).unwrap();

        for node in path.split("/") {
            if node.is_empty() {
                continue;
            }

            if re.is_match(node) {
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
        if &path[path.len() - 1..] == "/" {
            p += "/";
        }

        p
    }
}

#[cfg(test)]
mod tests {

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
        let mut r = Router::default();
        r.has_slash();

        r.post("/:user/:id", |c| {});

        let mut g = r.group("/:v1");
        {
            g.get("admin/:name:i32", |mut c| {
                c += "x";
            });
            g.post("/admin/u32/", |c| {});

            let mut g1 = g.group("/test1");
            {
                g1.put("admin/login/", |c| {});
                g1.delete("/admin/login1/", |c| {});
            }
        }

        let mut g = r.group("/a1/");
        {
            g.add(Method::GET, "/admin/login", |c| {});
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
        let re = Regex::new(r#"^:(?P<name>[a-zA-a_]{1}[a-zA-Z_0-9]*?):(?P<reg>i32|u32|i8|u8|i64|u64|i128|u128|isize|usize|bool)$"#).unwrap();

        let data = ":name:usize";
        let v = re.captures(data).unwrap();
        let r = v.name("name").unwrap();
        println!("{:?}", r.as_str());
        let r = v.name("reg").unwrap();
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

        assert_eq!(r"/admin/(?P<name>.*+?)/info/(?P<id>\d+?)/name/", p.as_str());
    }

    #[test]
    fn test_path_param_to_regex() {
        let path = "/user/:id:u32/:page:u32";
        let p = Route::path_param_type_to_regex(path);
        assert_eq!(r"/user/:id:(\d{1,10})/:page:(\d{1,10})", p.as_str());
    }

    #[test]
    fn test_router_match() {
        let mut r = Router::default();

        let mut g = r.group("/v1");
        {
            g.before(Method::ANY, "admin/:name", |c| {
                println!("before admin:{}", c);
            });
            g.after(Method::ANY, "admin/:name", |c| {
                println!("after after:{}", c);
            });
            
            g.any("admin/:name:i32", |c| {
                println!("admin:{}", c);
            });
            g.any("admin/:name", |c| {
                println!("admin:{}", c);
            });
            g.any("admin/:name/:id:u32", |c| {
                println!("admin:{}", c);
            });
            g.post("/admin/login1/", |c| {
                println!("login1:{}", c);
            });
        }

        // println!("{:#?}", r);

        let route = r.match_route(Method::GET, "/v1/admin/zhang山/23423");
        println!("route:{:#?}", route);

        // (route.as_ref().unwrap().route.unwrap().handler)("xxx".to_string());
    }

    #[test]
    fn test_filters() {}
}
