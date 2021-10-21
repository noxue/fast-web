use regex::Regex;

/// 包含了请求的所有信息以及用户自定义信息
type Context = String;

/// 请求处理函数
type Handler = fn(Context);

#[derive(Debug)]
enum Method {
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
}

impl Router {
    pub fn group(&mut self, path: &str) -> RouterGroup {
        RouterGroup::new(path, self)
    }
    fn add(&mut self, method: Method, path: String, handler: Handler) {
        assert!(path.len() > 0);

        let route = Route::new(method, path.to_owned(), handler, None);
        self.routes.push(route);
    }
}

pub struct RouterGroup<'a> {
    path: String,
    router: &'a mut Router,
}

impl<'a> RouterGroup<'a> {
    fn new(path: &str, router: &'a mut Router) -> Self {
        Self {
            path: path.to_lowercase(),
            router: router,
        }
    }

    fn concat_path(&self, path1: &str, path2: &str) -> String {
        // 两个路径除去斜杠之后，必须不为空
        assert!(path1.replace("/", "").len() > 0 && path2.replace("/", "").len() > 0);
        let mut new_path = path1.to_string();
        if &path1[path1.len() - 1..] == "/" && &path2[0..1] == "/" {
            // 防止路径连接的时候产生两个斜杠
            new_path = path1.to_string() + &path2[1..];
        } else if &path1[path1.len() - 1..] != "/" && &path2[0..1] != "/" {
            // 前后连接处都没有 斜线的情况，就在中间加一个斜线
            new_path = path1.to_string() + "/" + &path2[1..];
        } else {
            new_path += path2;
        }
        new_path
    }

    fn add(&mut self, method: Method, path: &str, handler: Handler) {
        let path = self.concat_path(self.path.as_str(), path);

        self.router.add(method, path, handler);
    }

    pub fn group(&mut self, path: &str) -> RouterGroup {
        let path = self.concat_path(self.path.as_str(), path);
        RouterGroup::new(path.as_str(), self.router)
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
}

impl Route {
    fn new(method: Method, path: String, handler: Handler, name: Option<String>) -> Self {
        // let path = path.replace("//", "/");
        Self {
            method,
            path: path.to_lowercase(),
            name,
            re: Regex::new(path.as_str()).unwrap(),
            handler,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::Method;
    use super::Route;
    use super::Router;

    #[test]
    fn test_router() {
        let mut r = Router::default();
        let mut g = r.group("/v1");
        {
            g.add("get".into(), "admin/:name:(.*?)", |c| {});
            g.add("get".into(), "/admin/login1", |c| {});

            let mut g1 = g.group("/test1");
            {
                g1.add("get".into(), "admin/login", |c| {});
                g1.add("get".into(), "/admin/login1", |c| {});
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
}
