import{a as o,o as c,b as i,e,f as d,w as r,h as _,p,i as l,j as h}from"./entry.c2a429a7.js";const u={data(){return{message:""}},async mounted(){await(await fetch("/api/v1/user",{credentials:"include",headers:{"Content-type":"application/json"}})).json()}},s=t=>(p("data-v-c39dda9e"),t=t(),l(),t),m={class:"top-banner-section"},x=s(()=>e("div",{class:"banner-image-div"},[e("img",{class:"banner-image",src:"https://plus.unsplash.com/premium_photo-1661678079655-10fe58ab8d30?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxlZGl0b3JpYWwtZmVlZHw3fHx8ZW58MHx8fHw%3D&auto=format&fit=crop&w=500&q=60",alt:"Banner Image"})],-1)),b=s(()=>e("div",{class:"banner-overlay-div"},null,-1)),v={class:"banner-text-div"},f={class:"banner-text"},g=s(()=>e("p",{class:"banner-h1-text"},"Remain relevant in today's technology-driven economy",-1)),w=s(()=>e("p",{class:"banner-body-text"}," Learn how agile can give you a competitive edge. Let Go.. ",-1)),y={class:"banner-btn"},B=h("Get started \u2192");function H(t,a,I,j,M,N){const n=_;return c(),i("section",m,[x,b,e("div",v,[e("span",f,[g,w,e("p",y,[d(n,{class:"banner-btn-item",to:"/register"},{default:r(()=>[B]),_:1})])])])])}const Z=o(u,[["render",H],["__scopeId","data-v-c39dda9e"]]);export{Z as default};