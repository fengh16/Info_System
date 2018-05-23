// 纯原生js做一下收缩效果
function hasClass( elements,cName ){
    return !!elements.className.match( new RegExp( "(\\s|^)" + cName + "(\\s|$)") ); // ( \\s|^ ) 判断前面是否有空格 （\\s | $ ）判断后面是否有空格 两个感叹号为转换为布尔值 以方便做判断
}
function addClass( elements,cName ){
    if( !hasClass( elements,cName ) ){
        elements.className += " " + cName;
    }
}
function removeClass( elements,cName ){
    if( hasClass( elements,cName ) ){
        elements.className = elements.className.replace( new RegExp( "(\\s|^)" + cName + "(\\s|$)" )," " ); // replace方法是替换
    }
}
document.getElementById("hide_or_show").onclick = function () {
    var elem=document.getElementsByTagName("nav")[0];
    if(!hasClass(elem, "td-header--is-open")) addClass(elem, "td-header--is-open");
    else removeClass(elem, "td-header--is-open")
};
function footerresize(){
    // console.log("Resize!");
    // console.log(document.body.clientWidth);
    // console.log(document.getElementsByTagName("footer")[0].clientHeight);
    // console.log(document.getElementsByClassName("footer-position")[0].style.height);
    document.getElementsByTagName("footer")[0].style.visibility="visible";
    document.getElementsByClassName("footer-position")[0].style.height= (20 + document.getElementsByTagName("footer")[0].clientHeight).toString() + "px"
    console.log(window.innerHeight);
    console.log(document.getElementsByTagName("footer")[0].clientHeight)
    console.log(document.getElementsByTagName("footer")[0].clientHeight * 5 / 2)
    if(window.innerHeight < document.getElementsByTagName("footer")[0].clientHeight * 5 / 2) {
        document.getElementsByTagName("footer")[0].style.visibility="hidden";
        document.getElementsByClassName("footer-position")[0].style.height= "0px"
    }
}
document.getElementsByTagName("body")[0].onresize = function() {footerresize()};
function selectValue(sId,value){
    var s = document.getElementById(sId);
    var ops = s.options;
    for(var i=0;i<ops.length; i++){
        var tempValue = ops[i].value;
        if(tempValue == value)
        {
            ops[i].selected = true;
        }
    }
}
function changedLang() {
    var frame = document.createElement("iframe");
    frame.name="iframe";
    var m = document.getElementById("langChoose").value;
    var temp = document.createElement("form");
    temp.method = "post";
    temp.style.display = "none";
    temp.action = document.getElementById("langChoose").getAttribute("name");
    temp.target = "iframe";
    var opt = document.createElement("textarea");
        opt.name = "lang";
        opt.value = m;
        temp.appendChild(opt);
    document.body.appendChild(temp);
    document.body.appendChild(frame);
    temp.submit();
    setTimeout(function(){location.reload()}, 500);
}