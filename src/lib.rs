pub mod router;

// use std::{
//     borrow::BorrowMut,
//     cell::Cell,
//     collections::{HashMap, LinkedList},
//     hash::Hash,
//     ops::Deref,
//     ptr::NonNull,
//     str::FromStr,
//     sync::Arc,
//     vec,
// };

// type Handler = fn(&str);

// #[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
// enum Method {
//     TRACE,
//     HEAD,
//     GET,
//     POST,
//     PUT,
//     PATCH,
//     DELETE,
//     OPTIONS,
//     ANY,
// }

// impl From<Method> for String {
//     fn from(v: Method) -> Self {
//         format!("{:?}", v)
//     }
// }

// impl From<&str> for Method {
//     fn from(s: &str) -> Self {
//         match s.to_uppercase().as_str() {
//             "TRACE" => Self::TRACE,
//             "HEAD" => Self::HEAD,
//             "GET" => Self::GET,
//             "POST" => Self::POST,
//             "PUT" => Self::PUT,
//             "PATCH" => Self::PATCH,
//             "DELETE" => Self::DELETE,
//             "OPTIONS" => Self::OPTIONS,
//             "ANY" => Self::ANY,
//             v => panic!("不存在这个类型:{}", v),
//         }
//     }
// }

// struct Router {
//     routes: HashMap<String, HashMap<String, Route>>,
// }

// impl Router {
//     fn new() -> Self {
//         let mut routes: HashMap<String, HashMap<String, Route>> = HashMap::new();

//         let k = Method::TRACE.into();

//         routes.insert(k, HashMap::new());
//         routes.insert(Method::HEAD.into(), HashMap::new());
//         routes.insert(Method::GET.into(), HashMap::new());
//         routes.insert(Method::POST.into(), HashMap::new());
//         routes.insert(Method::PUT.into(), HashMap::new());
//         routes.insert(Method::PATCH.into(), HashMap::new());
//         routes.insert(Method::DELETE.into(), HashMap::new());
//         routes.insert(Method::OPTIONS.into(), HashMap::new());
//         routes.insert(Method::ANY.into(), HashMap::new());
//         Router {
//             routes,
//         }
//     }

//     fn add(&mut self, method: Method, uri: &str, handler: Handler) {
//         let nodes: Vec<&str> = uri.split('/').filter(|v| !v.is_empty()).collect();

//         let k: String = method.into();
//         let mut routes = self.routes.get_mut(&k).unwrap();

//         for v in nodes {
//             // 如果是已经存在的路由，就跳到下一个
//             if let Some(v) = routes.get(v) {
//                 routes = unsafe { v.children_routes.unwrap().as_mut() };
//                 continue;
//             }

//             let route = Route::new(v);
//             let v = Box::leak(Box::new(&route));
//             let tr = unsafe { v.children_routes.unwrap().as_mut() };
//             routes.insert(method.into(), route);
//             routes = tr;
//         }
//     }
// }

// /// 路由节点
// #[derive(Default)]
// struct Route {
//     node: String, // 节点名称, 之包含地址中的一段，例： /admin/login就是两个节点 node就保存 admin或者login
//     children_routes: Option<NonNull<HashMap<String, Route>>>, // 下级分支节点
//     handlers: Option<Vec<Handler>>, // 节点对应的处理器
//     is_end: bool, // 是否是最后一个节点， true表示是最后一个节点
// }

// impl Route {
//     fn new(node: &str) -> Self {
//         let v: HashMap<String, Route> = HashMap::new();
//         Route {
//             node: node.to_string(),
//             children_routes: Some(Box::leak(Box::new(v)).into()),
//             handlers: None,
//             is_end: false,
//         }
//     }
// }

// #[derive(Default)]
// struct RouteGroup {
//     route: Route,
// }

// impl RouteGroup {}

// #[cfg(test)]
// mod tests {
//     use std::collections::HashMap;

//     use crate::{Method, Route, Router};

//     #[test]
//     fn test_router_add() {

//         let mut r = Router::new();

 
//         r.add(Method::GET, "/admin/user/123", |v| {});
//         r.add(Method::GET, "/admin/name/123", |v| {});

//         let k: String = Method::GET.into();
//         let root = r.routes.get(&k).unwrap();
//         println!("len:{:?}", root.len());

//         let c = root.get("GET").unwrap();
//         for v in c.children_routes{
//             let v =unsafe {
//                 v.as_ref()
//             };
//             for v in v{
//                 println!("{:?}", v.0);
//             }
            
//         }

//         // fn show(r: &Route) {
//         //     println!("{}", r.node);
//         //     print!("\t");

//         //     if let None = r.children_routes {
//         //         return;
//         //     }

//         //     let cs = unsafe { r.children_routes.unwrap().as_mut() };
//         //     for v in cs {
//         //         show(v);
//         //     }
//         // }
//         // for v in r.routes {
//         //     for j in &v.1 {
//         //         show(j);
//         //     }
//         // }
//     }

//     #[test]
//     fn test() {
//         let v: String = Method::DELETE.into();
//         println!("{}", v);
//     }
// }
