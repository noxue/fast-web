//! 
//! ## 目标
//! 
//! 实现简单易用，且能快速上手的 rust web 框架，参考了`rust`的`reset-router`库的设计以及`golang`的`gin`库
//! 
//! 
//! ## 简单例子
//! ```
//! // use env_logger::{self, Env};
//! use fast_web::router::{Ctx, Router};
//! 
//! // 首页处理器
//! fn index(c: &mut Ctx) {
//!     c.string("欢迎光临，<a href='articles'>点击打开文章列表</a>");
//! }
//! 
//! fn main() {
//!     // env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();
//! 
//!     let mut r = Router::default();
//! 
//!     let v = "1234567".to_string();
//! 
//!     // 所有页面都会被设置token头
//!     r.before("any".into(), "", move |c| {
//!         c.set_header("token", &v);
//!     });
//! 
//!     // 首页
//!     r.get("", index);
//! 
//!     // 文章分组
//!     let mut article = r.group("articles");
//!     {
//!         article.get("", |c| {
//!             c.string("文章列表<ul><li><a href='/articles/1'>第 1 篇文章</a></li><li><a href='/articles/2/'>第 2 篇文章</a></li></ul>");
//!         });
//! 
//!         article.get("/:id:i32", |c| {
//!             let id: i32 = c.param("id").unwrap();
//!             c.string(format!("这是第 {} 篇文章", id).as_str());
//!         });
//!     }
//! 
//!     r.run("127.0.0.1:80");
//! }
//! ```

pub use serde_derive;

/// 路由功能
pub mod router;