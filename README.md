# Info_System

一个使用Flask和MongoDB的信息发布系统，具有以下功能：

* 用户权限管理：
  * 一个超级管理员（第一次注册时通过管理员通道注册，不输入安全码）
  * 若干不同级别管理员（注册时需要提供超级管理员的对应安全码），根据级别不同分别具有发布信息、管理帖子、管理用户等权限
  * 普通用户：可以查看信息
* 信息存储&显示：
  * 按照不同分类存储相关信息，通过用户注册时选择的分类提供不同类目信息的显示
* 语言切换：
  * 定义并实现翻译的函数，根据用户偏好设置来显示语言

~~在 [这里](http://foxandbunny.me/) 有一个运行中的示例程序，超级管理员账号：superadmin，密码：jioj@#ji23gQ23~~
(已经删除该站点）
