<?php
/**
 * EasyWebDAV - Single File WebDAV Server & File Manager
 * Optimized for UI/UX and Performance
 * By Prince | https://github.com/Andeasw/EasyWebDAV-PHP
 */
@error_reporting(0); @set_time_limit(0); @ignore_user_abort(true);
date_default_timezone_set('PRC');

if(session_status()===PHP_SESSION_NONE) session_start();
if(empty($_SESSION['t'])) $_SESSION['t']=bin2hex(random_bytes(32));
$csrf=$_SESSION['t'];

define('ROOT',__DIR__);
define('S_NAME',basename($_SERVER['SCRIPT_NAME']));
define('BASE',(isset($_SERVER['HTTPS'])&&$_SERVER['HTTPS']==='on'?'https':'http')."://".$_SERVER['HTTP_HOST'].$_SERVER['SCRIPT_NAME']);
define('S_PATH',ROOT.'/storage');
define('AUTH_F',ROOT.'/.htpasswd.php');
define('SHARE_F',ROOT.'/.shares.php');
define('DENY',['.','..','.htaccess','.htpasswd.php','.shares.php',S_NAME,basename(__FILE__)]);

if(!file_exists(S_PATH)) @mkdir(S_PATH,0755,true);
if(!file_exists(S_PATH.'/.htaccess')) @file_put_contents(S_PATH.'/.htaccess',"Deny from all");
if(!file_exists(ROOT.'/.htaccess')) @file_put_contents(ROOT.'/.htaccess',"Options -Indexes\nRewriteEngine On\nRewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]");

if(!file_exists(AUTH_F)){
    if(!empty($_SERVER['PHP_AUTH_USER'])&&!empty($_SERVER['PHP_AUTH_PW'])){
        @file_put_contents(AUTH_F,"<?php return ".var_export(['u'=>$_SERVER['PHP_AUTH_USER'],'h'=>password_hash($_SERVER['PHP_AUTH_PW'],PASSWORD_DEFAULT)],true).";");
    } else {
        header('WWW-Authenticate: Basic realm="Install"'); header('HTTP/1.0 401 Unauthorized'); die('Init: Login with desired admin creds.');
    }
}
$ac=include AUTH_F; $u=$_SERVER['PHP_AUTH_USER']??''; $p=$_SERVER['PHP_AUTH_PW']??'';
if($u!==$ac['u']||!password_verify($p,$ac['h'])){
    $h=$_SERVER['HTTP_AUTHORIZATION']??($_SERVER['REDIRECT_HTTP_AUTHORIZATION']??'');
    if($h&&preg_match('/Basic\s+(.*)$/i',$h,$m)) list($u,$p)=explode(':',base64_decode($m[1]),2);
    if($u!==$ac['u']||!password_verify($p,$ac['h'])){
        header('WWW-Authenticate: Basic realm="EasyWebDAV"'); header('HTTP/1.0 401 Unauthorized'); die('Access Denied');
    }
}

$lang=$_COOKIE['l']??'cn';
$L=['cn'=>['up'=>'上传','new'=>'新建文件夹','cr'=>'创建','nm'=>'名称','sz'=>'大小','tm'=>'修改时间','ac'=>'操作','dl'=>'下载','rn'=>'重命名','cp'=>'复制','mv'=>'移动','rm'=>'删除','sh'=>'分享','emp'=>'空目录','tip'=>'确认删除','lnk'=>'直链地址','cpl'=>'复制链接','ok'=>'确定','cc'=>'取消','tar'=>'目标路径','sh_m'=>'分享管理','sh_new'=>'新建分享','sh_up'=>'更新密钥','sh_rnd'=>'随机生成','sh_cus'=>'自定义','sh_del'=>'取消分享','sh_ok'=>'分享链接已更新'],
    'en'=>['up'=>'Upload','new'=>'New Folder','cr'=>'Create','nm'=>'Name','sz'=>'Size','tm'=>'Modified','ac'=>'Actions','dl'=>'Download','rn'=>'Rename','cp'=>'Copy','mv'=>'Move','rm'=>'Delete','sh'=>'Share','emp'=>'Empty','tip'=>'Delete','lnk'=>'Link','cpl'=>'Copy Link','ok'=>'OK','cc'=>'Cancel','tar'=>'Target Path','sh_m'=>'Share Manager','sh_new'=>'New Share','sh_up'=>'Update Key','sh_rnd'=>'Random','sh_cus'=>'Custom','sh_del'=>'Unshare','sh_ok'=>'Share Link Updated']];
if(isset($_GET['l'])){setcookie('l',$_GET['l'],time()+31536000);header("Location: ".BASE);exit;}
function T($k){global $L,$lang;return $L[$lang][$k]??$k;}

$dav=new Dav();
if($_SERVER['REQUEST_METHOD']==='POST'){
    if(isset($_FILES['f'])||isset($_POST['md'])||isset($_POST['act'])||isset($_POST['s_act'])) $dav->handleBrowser();
    else $dav->serve();
} elseif(isset($_GET['s'])) $dav->publicShare($_GET['s']);
else $dav->serve();

class Dav {
    private $uri, $req, $path;
    public function __construct(){
        $this->uri=$_SERVER['SCRIPT_NAME'];
        $u=rawurldecode(explode('?',$_SERVER['REQUEST_URI'])[0]);
        $this->req=(strpos($u,$this->uri)===0)?substr($u,strlen($this->uri)):$u;
        $this->req=empty($this->req)?'/':$this->req;
        $p=[]; foreach(explode('/',str_replace('\\','/',$this->req)) as $k) if($k!==''&&$k!=='.'&&$k!=='..') $p[]=$k;
        $this->path=S_PATH.DIRECTORY_SEPARATOR.implode(DIRECTORY_SEPARATOR,$p);
    }
    private function chk(){global $csrf;if(($_POST['t']??'')!==$csrf)die('CSRF Error');}
    private function isP($n){return in_array($n,DENY);}
    private function back($q=''){header("Location: ".$_SERVER['REQUEST_URI'].$q);exit;}

    public function serve(){
        try {
            switch($_SERVER['REQUEST_METHOD']){
                case 'GET': $this->GET(); break;
                case 'PUT': $this->PUT(); break;
                case 'DELETE': $this->DEL(); break;
                case 'MKCOL': $this->MKCOL(); break;
                case 'PROPFIND': $this->PROP(); break;
                case 'COPY': $this->CPMV(0); break;
                case 'MOVE': $this->CPMV(1); break;
                case 'OPTIONS': header('DAV: 1, 2'); header('Allow: OPTIONS, GET, HEAD, DELETE, PROPFIND, PUT, MKCOL, COPY, MOVE'); exit;
                case 'HEAD': file_exists($this->path)?http_response_code(200):http_response_code(404); break;
            }
        } catch(Exception $e){http_response_code(500);}
    }

    public function handleBrowser(){
        $this->chk(); $act=$_POST['act']??''; $n=basename($_POST['n']??'');
        if(isset($_FILES['f'])&&!$_FILES['f']['error']&&!$this->isP($_FILES['f']['name'])) move_uploaded_file($_FILES['f']['tmp_name'],$this->path.'/'.$_FILES['f']['name']);
        elseif(isset($_POST['md'])&&($d=trim($_POST['md']))&&!$this->isP($d)) @mkdir($this->path.'/'.$d);
        elseif($act&&$n&&!$this->isP($n)){
            $t=$this->path.'/'.$n;
            if($act==='rn'&&($nn=trim($_POST['nn']??''))&&!$this->isP($nn)) rename($t,dirname($t).'/'.$nn);
            elseif($act==='rm') $this->rm($t);
            elseif(($act==='cp'||$act==='mv')&&($tg=$_POST['tg']??'')){
                $dst=S_PATH.'/'.ltrim($tg,'/').'/'.$n;
                if(!$this->isP(basename($dst))) $act==='mv'?rename($t,$dst):$this->cp($t,$dst);
            }
        } elseif(isset($_POST['s_act'])){
            $s=file_exists(SHARE_F)?include SHARE_F:[]; if(!is_array($s))$s=[];
            $sa=$_POST['s_act']; $nt=$_POST['ntok']??''; $ot=$_POST['otok']??'';
            if($sa==='c' || $sa==='u') {
                $rel=ltrim(substr($this->path.'/'.$n,strlen(S_PATH)),'/');
                if($sa==='u' && isset($s[$ot])) unset($s[$ot]); 
                if($sa==='c') foreach($s as $k=>$v) if($v===$rel) unset($s[$k]); 
                $newT = ($sa==='u' && $nt) ? $nt : bin2hex(random_bytes(6));
                if(isset($s[$newT]) && $s[$newT]!==$rel) $newT = bin2hex(random_bytes(6)); 
                $s[$newT]=$rel;
                file_put_contents(SHARE_F,"<?php return ".var_export($s,true).";");
                $this->back('?s_new='.$newT);
            } elseif($sa==='d') {
                if(isset($s[$ot])) unset($s[$ot]);
                file_put_contents(SHARE_F,"<?php return ".var_export($s,true).";");
            }
        }
        $this->back();
    }

    public function publicShare($k){
        $s=file_exists(SHARE_F)?include SHARE_F:[];
        if(isset($s[$k])&&file_exists($f=S_PATH.'/'.$s[$k])){
            header('Content-Type: '.$this->mime($f)); header('Content-Disposition: attachment; filename="'.basename($f).'"');
            header('Content-Length: '.filesize($f)); readfile($f); exit;
        }
        http_response_code(404); die('Link Expired');
    }

    private function GET(){
        if(!file_exists($this->path)){http_response_code(404);exit;}
        if(is_dir($this->path)){$this->HTML();exit;}
        if($this->isP(basename($this->path))){http_response_code(403);exit;}
        $dl=isset($_GET['dl']); header('Content-Type: '.($dl?'application/octet-stream':$this->mime($this->path)));
        header('Content-Length: '.filesize($this->path)); header('ETag: "'.md5($this->path.filemtime($this->path)).'"');
        header('Content-Disposition: '.($dl?'attachment':'inline').'; filename="'.basename($this->path).'"');
        readfile($this->path); exit;
    }

    private function PUT(){
        if($this->isP(basename($this->path))){http_response_code(403);exit;}
        if(!is_dir(dirname($this->path))) mkdir(dirname($this->path),0755,true);
        $i=fopen('php://input','r'); $o=fopen($this->path,'w');
        if($i&&$o){stream_copy_to_stream($i,$o);http_response_code(201);}else http_response_code(500);
    }

    private function DEL(){if(file_exists($this->path)&&$this->path!=S_PATH){$this->rm($this->path);http_response_code(204);}else http_response_code(403);}
    private function MKCOL(){mkdir($this->path,0755,true)?http_response_code(201):http_response_code(409);}
    private function PROP(){
        if(!file_exists($this->path)){http_response_code(404);exit;}
        header('HTTP/1.1 207 Multi-Status');header('Content-Type: application/xml; charset="utf-8"');
        echo '<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">';
        $fs=is_dir($this->path)?array_merge([$this->path],($_SERVER['HTTP_DEPTH']??1)!=0?glob($this->path.'/*'):[]):[$this->path];
        foreach($fs as $f){
            if($this->isP(basename($f)))continue;
            $href=$this->uri.str_replace('%2F','/',rawurlencode(str_replace('\\','/',substr($f,strlen(S_PATH)))));
            echo '<D:response><D:href>'.$href.'</D:href><D:propstat><D:prop><D:displayname>'.htmlspecialchars(basename($f)).'</D:displayname><D:getlastmodified>'.gmdate('D, d M Y H:i:s T',filemtime($f)).'</D:getlastmodified>';
            echo is_dir($f)?'<D:resourcetype><D:collection/></D:resourcetype>':'<D:resourcetype/><D:getcontentlength>'.filesize($f).'</D:getcontentlength>';
            echo '</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>';
        } echo '</D:multistatus>';
    }
    private function CPMV($mv){
        $d=rawurldecode(parse_url($_SERVER['HTTP_DESTINATION']??'',PHP_URL_PATH));
        if(strpos($d,$this->uri)===false){http_response_code(502);exit;}
        $t=S_PATH.'/'.implode('/',array_filter(explode('/',substr($d,strpos($d,$this->uri)+strlen($this->uri))),fn($p)=>$p!==''&&$p!=='.'&&$p!=='..'));
        if($this->isP(basename($t))){http_response_code(403);exit;}
        if(file_exists($t)){if(($_SERVER['HTTP_OVERWRITE']??'T')==='F'){http_response_code(412);exit;} $this->rm($t);}
        $mv?rename($this->path,$t):$this->cp($this->path,$t); http_response_code(201);
    }
    private function rm($p){if(is_dir($p)){foreach(scandir($p)as $i)if($i!='.'&&$i!='..')$this->rm($p.'/'.$i);rmdir($p);}else unlink($p);}
    private function cp($s,$d){if(is_dir($s)){if(!file_exists($d))mkdir($d,0755,true);foreach(scandir($s)as $i)if($i!='.'&&$i!='..')$this->cp($s.'/'.$i,$d.'/'.$i);}else copy($s,$d);}
    private function mime($f){$x=strtolower(pathinfo($f,4));$m=['txt'=>'text/plain','html'=>'text/html','css'=>'text/css','js'=>'text/javascript','json'=>'application/json','jpg'=>'image/jpeg','png'=>'image/png','gif'=>'image/gif','mp4'=>'video/mp4','pdf'=>'application/pdf','zip'=>'application/zip'];return $m[$x]??'application/octet-stream';}
    private function size($b){$u=['B','KB','MB','GB'];$i=0;while($b>=1024&&$i<3){$b/=1024;$i++;}return round($b,2).' '.$u[$i];}

    private function HTML(){
        global $csrf,$lang;$l=scandir($this->path);
        usort($l,fn($a,$b)=>is_dir($this->path.'/'.$a)===is_dir($this->path.'/'.$b)?strcasecmp($a,$b):(is_dir($this->path.'/'.$a)?-1:1));
        $bc=[];$acc='';foreach(array_filter(explode('/',$this->req))as $p){$acc.='/'.$p;$bc[]=['n'=>$p,'u'=>$this->uri.implode('/',array_map('rawurlencode',explode('/',$acc)))];}
        $sh=file_exists(SHARE_F)?include SHARE_F:[];$sm=[];if(is_array($sh))foreach($sh as $k=>$v)$sm[$v]=$k;
        $newS=$_GET['s_new']??'';
        $I=['f'=>'<svg class="i" viewBox="0 0 24 24"><path fill="currentColor" d="M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6z"/></svg>',
            'd'=>'<svg class="i" viewBox="0 0 24 24" style="color:#f5c518"><path fill="currentColor" d="M10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>',
            'dl'=>'<svg viewBox="0 0 24 24"><path fill="currentColor" d="M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z"/></svg>',
            'sh'=>'<svg viewBox="0 0 24 24"><path fill="currentColor" d="M18 16.08c-.76 0-1.44.3-1.96.77L8.91 12.7c.05-.23.09-.46.09-.7s-.04-.47-.09-.7l7.05-4.11c.54.5 1.25.81 2.04.81 1.66 0 3-1.34 3-3s-1.34-3-3-3-3 1.34-3 3c0 .24.04.47.09.7L8.04 9.81C7.5 9.31 6.79 9 6 9c-1.66 0-3 1.34-3 3s1.34 3 3 3c.79 0 1.5-.31 2.04-.81l7.12 4.16c-.05.21-.08.43-.08.65 0 1.61 1.31 2.92 2.92 2.92 1.61 0 2.92-1.31 2.92-2.92s-1.31-2.92-2.92-2.92z"/></svg>',
            'ed'=>'<svg viewBox="0 0 24 24"><path fill="currentColor" d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>',
            'cp'=>'<svg viewBox="0 0 24 24"><path fill="currentColor" d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>',
            'mv'=>'<svg viewBox="0 0 24 24"><path fill="currentColor" d="M10 9h4V6h3l-5-5-5 5h3v3zm-1 1H6V7l-5 5 5 5v-3h3v-4zm14 2l-5-5v3h-3v4h3v3l5-5zm-9 3h-4v3H7l5 5 5-5h-3v-3z"/></svg>',
            'rm'=>'<svg viewBox="0 0 24 24"><path fill="currentColor" d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>'];
?>
<!DOCTYPE html><html lang="<?=$lang?>"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>EasyWebDAV-PHP</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;charset=utf-8,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64' width='64' height='64'%3E%3Cdefs%3E%3ClinearGradient id='a' x1='0' y1='0' x2='1' y2='1'%3E%3Cstop offset='0%25' stop-color='%2364B5F6'/%3E%3Cstop offset='100%25' stop-color='%232196F3'/%3E%3C/linearGradient%3E%3C/defs%3E%3Cpath fill='url(%23a)' d='M18 46h28c7 0 12-5.5 12-12 0-6-4.3-10.8-10.2-11.7C45.5 15 39.3 11 32 11s-13.5 4-15.8 11.3C10.3 23.2 6 28 6 34c0 6.5 5 12 12 12z'/%3E%3C/svg%3E">
<style>
:root{--bg-g:linear-gradient(135deg,#FEF9E7 0%,#E8F8F5 100%);--bg:rgba(255,255,255,0.85);--tx:#4b5563;--bd:#E2E8F0;--hv:#F1F5F9;--p:#14B8A6;--pd:#0F766E;--ac:#84CC16;--er:#F43F5E;--sh:0 10px 30px -10px rgba(0,0,0,0.05);}
.dark{--bg-g:linear-gradient(135deg,#0f172a 0%,#1e293b 100%);--bg:rgba(30,41,59,0.9);--tx:#e2e8f0;--bd:#334155;--hv:#334155;--p:#2dd4bf;--pd:#14b8a6;--ac:#a3e635;--er:#fb7185;}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg-g);color:var(--tx);min-height:100vh;background-attachment:fixed;display:flex;justify-content:center;align-items:start;padding-top:30px;box-sizing:border-box}
.box{width:95%;max-width:1100px;min-height:85vh;background:var(--bg);border-radius:20px;box-shadow:var(--sh);border:1px solid var(--bd);display:flex;flex-direction:column;overflow:hidden;backdrop-filter:blur(15px)}
header{padding:18px 26px;border-bottom:1px solid var(--bd);display:flex;justify-content:space-between;align-items:center;background:rgba(255,255,255,0.4);flex-shrink:0}
.dark header{background:rgba(0,0,0,0.2)}
.nav a{text-decoration:none;color:var(--tx);padding:6px 10px;border-radius:8px;transition:.2s;font-weight:500}.nav a:hover{background:var(--p);color:#fff}
.bar{padding:14px 26px;background:var(--hv);border-bottom:1px solid var(--bd);display:flex;gap:12px;align-items:center;flex-wrap:wrap;flex-shrink:0}
.btn{padding:8px 16px;border:1px solid var(--bd);background:#fff;border-radius:10px;cursor:pointer;font-size:14px;color:var(--tx);text-decoration:none;display:inline-flex;align-items:center;gap:6px;transition:.2s;font-weight:600;box-shadow:0 1px 2px rgba(0,0,0,0.03)}
.dark .btn{background:#1e293b}
.btn:hover{border-color:var(--p);color:var(--p);transform:translateY(-1px)}
.bp{background:var(--p);color:#fff;border:none}.bp:hover{background:var(--pd);color:#fff;opacity:0.9}
.bd{color:var(--er);border-color:transparent}.bd:hover{background:var(--er);color:#fff}
.main{flex:1;overflow-x:auto;display:flex;flex-direction:column}
table{width:100%;border-collapse:collapse;min-width:650px} 
th{text-align:left;padding:16px 26px;color:var(--pd);font-size:12px;font-weight:700;text-transform:uppercase;border-bottom:1px solid var(--bd);background:rgba(20,184,166,0.06);position:sticky;top:0}
td{padding:14px 26px;border-bottom:1px solid var(--bd);font-size:14px;vertical-align:middle} tr:hover td{background:var(--hv)}
.lnk{text-decoration:none;color:var(--tx);display:flex;align-items:center;gap:12px;font-weight:500;transition:.2s} .lnk:hover{color:var(--p)}
.i{width:24px;height:24px;color:#94a3b8} .acts{display:flex;gap:6px;justify-content:flex-end}
.ab{padding:7px;border:none;background:0 0;cursor:pointer;color:#94a3b8;border-radius:8px;display:flex;transition:.2s} .ab:hover{background:#ccfbf1;color:var(--p)} .dark .ab:hover{background:rgba(20,184,166,0.2)} .ab svg{width:18px;height:18px} .ab.del:hover{background:#fee2e2;color:var(--er)}
.mod{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.2);z-index:99;justify-content:center;align-items:center;backdrop-filter:blur(5px)}
.mb{background:#fff;padding:28px;border-radius:20px;width:90%;max-width:440px;box-shadow:0 25px 50px -12px rgba(0,0,0,0.15);border:1px solid var(--bd)}
.dark .mb{background:#1e293b}
.ft{padding:22px;text-align:center;font-size:13px;color:#94a3b8;background:var(--hv);border-top:1px solid var(--bd);display:flex;justify-content:center;align-items:center;gap:8px;flex-shrink:0}
.gh svg{width:20px;height:20px;fill:#94a3b8;transition:.2s} .gh:hover svg{fill:var(--p)}
.tg{background:0 0;border:none;cursor:pointer;padding:6px;border-radius:50%;color:var(--tx);transition:.2s}.tg:hover{background:rgba(0,0,0,0.05)}
.float-icon{animation:flt 3s ease-in-out infinite;display:block;filter:drop-shadow(0 0 6px #FDB813)} @keyframes flt{0%,100%{transform:translateY(0)}50%{transform:translateY(-4px)}}
@media(max-width:768px){body{padding:0;display:block}.box{margin:0;width:100%;max-width:none;border:none;border-radius:0;min-height:100vh}.hm{display:none}}
</style></head>
<body class="<?=$_COOKIE['dk']??''?>"><div class="box">
<header>
    <div class="nav"><a href="<?=$this->uri?>/"><?=T('home')?></a><?php foreach($bc as $b) echo ' / <a href="'.$b['u'].'">'.htmlspecialchars($b['n']).'</a>';?></div>
    <div style="display:flex;gap:12px;align-items:center">
        <button class="tg" onclick="mode()"><svg class="float-icon" width="24" height="24" viewBox="0 0 24 24" fill="#FDB813"><path d="M12 3c.132 0 .263 0 .393 0a7.5 7.5 0 0 0 7.92 12.446a9 9 0 1 1 -8.313 -12.454z"/></svg></button>
        <div style="font-size:13px;font-weight:600"><a href="?l=cn" style="text-decoration:none;color:<?=$lang=='cn'?'var(--p)':'#94a3b8'?>">CN</a> <span style="color:#cbd5e1">|</span> <a href="?l=en" style="text-decoration:none;color:<?=$lang=='en'?'var(--p)':'#94a3b8'?>">EN</a></div>
    </div>
</header>
<div class="bar">
    <?php if($this->req!=='/'): $pp=array_filter(explode('/',$this->req)); array_pop($pp); ?><a href="<?=$this->uri.'/'.implode('/',array_map('rawurlencode',$pp))?>" class="btn"><?=T('back')?></a><?php endif;?>
    <form method="post" enctype="multipart/form-data" style="margin:0"><input type="hidden" name="t" value="<?=$csrf?>"><label class="btn bp"><?=T('up')?><input type="file" name="f" hidden onchange="this.form.submit()"></label></form>
    <form method="post" style="display:flex;gap:8px;margin:0;flex:1"><input type="hidden" name="t" value="<?=$csrf?>"><input name="md" placeholder="<?=T('new')?>" required style="padding:8px 12px;border:1px solid var(--bd);border-radius:8px;outline:none;background:rgba(255,255,255,0.5);color:var(--tx);flex:1;min-width:100px;max-width:250px"><button class="btn"><?=T('cr')?></button></form>
</div>
<div class="main"><table><thead><tr><th><?=T('nm')?></th><th class="hm"><?=T('sz')?></th><th class="hm"><?=T('tm')?></th><th style="text-align:right"><?=T('ac')?></th></tr></thead><tbody>
<?php foreach($l as $f): if($this->isP($f))continue; $p=$this->path.'/'.$f; $d=is_dir($p); $lk=$this->uri.rtrim($this->req,'/').'/'.rawurlencode($f); $shr=isset($sm[$f])?$sm[$f]:''; ?>
<tr>
    <td><a href="<?=$lk?>" class="lnk" target="<?=$d?'_self':'_blank'?>"><?=$d?$I['d']:$I['f']?> <?=htmlspecialchars($f)?> <?php if($shr)echo '<span style="font-size:10px;color:var(--ac);background:rgba(132,204,22,.1);padding:2px 6px;border-radius:4px;font-weight:600">SHARED</span>';?></a></td>
    <td class="hm"><?=$d?'-':$this->size(filesize($p))?></td><td class="hm"><?=date('Y-m-d H:i',filemtime($p))?></td>
    <td><div class="acts">
        <?php if(!$d):?><a href="<?=$lk?>?dl=1" class="ab" title="<?=T('dl')?>"><?=$I['dl']?></a><button onclick="s('<?=$f?>','<?=$shr?>')" class="ab" title="<?=T('sh')?>"><?=$I['sh']?></button><?php endif;?>
        <button onclick="p('rn','<?=$f?>')" class="ab" title="<?=T('rn')?>"><?=$I['ed']?></button><button onclick="p('cp','<?=$f?>')" class="ab" title="<?=T('cp')?>"><?=$I['cp']?></button><button onclick="p('mv','<?=$f?>')" class="ab" title="<?=T('mv')?>"><?=$I['mv']?></button><button onclick="p('rm','<?=$f?>')" class="ab del" title="<?=T('rm')?>"><?=$I['rm']?></button>
    </div></td>
</tr>
<?php endforeach; if(count($l)<=2):?><tr><td colspan="4" style="text-align:center;padding:60px 20px;color:#94a3b8;font-style:italic"><?=T('emp')?></td></tr><?php endif;?>
</tbody></table></div>
<div class="ft">&copy; <?=date('Y')?> EasyWebDAV-PHP By Prince <a href="https://github.com/Andeasw/EasyWebDAV-PHP" target="_blank" class="gh"><svg viewBox="0 0 98 96"><path fill-rule="evenodd" clip-rule="evenodd" d="M48.854 0C21.839 0 0 22 0 49.217c0 21.756 13.993 40.172 33.405 46.69 2.427.49 3.316-1.059 3.316-2.362 0-1.141-.08-5.052-.08-9.127-13.59 2.934-16.42-5.867-16.42-5.867-2.184-5.704-5.42-7.17-5.42-7.17-4.448-3.015.324-3.015.324-3.015 4.934.326 7.523 5.052 7.523 5.052 4.367 7.496 11.404 5.378 14.235 4.074.404-3.178 1.699-5.378 3.074-6.6-10.839-1.141-22.243-5.378-22.243-24.283 0-5.378 1.94-9.778 5.014-13.2-.485-1.222-2.184-6.275.486-13.038 0 0 4.125-1.304 13.426 5.052a46.97 46.97 0 0 1 12.214-1.63c4.125 0 8.33.571 12.213 1.63 9.302-6.356 13.427-5.052 13.427-5.052 2.67 6.763.97 11.816.485 13.038 3.155 3.422 5.015 7.822 5.015 13.2 0 18.905-11.404 23.06-22.324 24.283 1.78 1.548 3.316 4.481 3.316 9.126 0 6.6-.08 11.897-.08 13.526 0 1.304.89 2.853 3.316 2.364 19.412-6.52 33.405-24.935 33.405-46.691C97.707 22 75.788 0 48.854 0z"/></svg></a></div>
</div>
<div id="md" class="mod"><div class="mb"><h3 id="mt" style="margin-top:0"></h3><div id="mc"></div><div style="margin-top:20px;text-align:right;display:flex;justify-content:flex-end;gap:10px"><button class="btn" onclick="cl()"><?=T('cc')?></button><button class="btn bp" id="mok"><?=T('ok')?></button></div></div></div>
<script>
const $=i=>document.getElementById(i), csrf='<?=$csrf?>', cur='<?=$this->req==='/'?'':$this->req?>';
const sNew='<?=$newS?>', base='<?=BASE?>';
function mode(){ document.body.classList.toggle('dark'); document.cookie='dk='+(document.body.classList.contains('dark')?'dark':'')+';path=/;max-age=31536000'; }
function cl(){ $('md').style.display='none'; }
function pf(h){ const f=document.createElement('form'); f.style.display='none'; f.method='post'; f.innerHTML=h; document.body.appendChild(f); f.submit(); }
function p(a,n){
    $('md').style.display='flex'; $('mt').innerText=(a=='rn'?'<?=T('rn')?>':(a=='cp'?'<?=T('cp')?>':(a=='mv'?'<?=T('mv')?>':'<?=T('rm')?>')));
    let h=''; if(a=='rm') h='<p><?=T('tip')?> "'+n+'"?</p>';
    else h='<input id="iv" value="'+(a=='rn'?n:cur)+'" style="width:100%;padding:10px;border:1px solid var(--bd);border-radius:8px;background:rgba(255,255,255,0.5);color:var(--tx);box-sizing:border-box" placeholder="'+(a=='rn'?'<?=T('nm')?>':'<?=T('tar')?>')+'">';
    $('mc').innerHTML=h; if($('iv')) setTimeout(()=>$('iv').focus(),50);
    $('mok').className='btn '+(a=='rm'?'bd':'bp'); $('mok').innerText=a=='rm'?'<?=T('rm')?>':'<?=T('ok')?>'; $('mok').style.display='inline-flex';
    $('mok').onclick=()=>{ let val=$('iv')?$('iv').value:''; pf('<input type="hidden" name="t" value="'+csrf+'"><input name="act" value="'+a+'"><input name="n" value="'+n+'"><input name="'+(a=='rn'?'nn':'tg')+'" value="'+val+'">'); }
}
function s(n,t){
    if(!t){ subS('c',n); return; }
    $('md').style.display='flex'; $('mt').innerText='<?=T('sh_m')?>';
    let lk=base+'?s='+t;
    let h='<div style="display:flex;gap:8px;margin-bottom:15px"><input id="lnk" value="'+lk+'" style="flex:1;padding:8px;border:1px solid var(--bd);border-radius:8px;background:var(--hv);color:var(--tx)" readonly><button class="btn" onclick="cp(\'lnk\')"><?=T('cpl')?></button></div>';
    h+='<div style="border-top:1px solid var(--bd);padding-top:15px;margin-top:10px"><div style="font-size:12px;color:#94a3b8;margin-bottom:8px"><?=T('sh_up')?></div><div style="display:flex;gap:8px;margin-bottom:8px"><button class="btn" style="flex:1" onclick="subS(\'u\',\''+n+'\',\'\',\''+t+'\')"><?=T('sh_rnd')?></button><div style="display:flex;flex:2;gap:4px"><input id="ctok" placeholder="<?=T('sh_cus')?>" style="flex:1;padding:6px;border:1px solid var(--bd);border-radius:8px;background:rgba(255,255,255,0.5);color:var(--tx)"><button class="btn" onclick="subS(\'u\',\''+n+'\',$(\'ctok\').value,\''+t+'\')"><?=T('ok')?></button></div></div></div>';
    h+='<div style="margin-top:15px"><button class="btn bd" style="width:100%" onclick="subS(\'d\',\''+n+'\',\'\',\''+t+'\')"><?=T('sh_del')?></button></div>';
    $('mc').innerHTML=h; $('mok').style.display='none';
}
function subS(a,n,nt,ot){ pf('<input type="hidden" name="t" value="'+csrf+'"><input name="s_act" value="'+a+'"><input name="n" value="'+n+'"><input name="ntok" value="'+(nt||'')+'"><input name="otok" value="'+(ot||'')+'">'); }
function cp(i){ navigator.clipboard.writeText($(i).value).then(()=>alert('<?=T('sh_ok')?>')); }
window.onclick=e=>{if(e.target.className==='mod')cl()};
if(sNew){
    $('md').style.display='flex'; $('mt').innerText='<?=T('sh_ok')?>';
    let lk=base+'?s='+sNew;
    $('mc').innerHTML='<div style="display:flex;gap:8px;margin-bottom:20px"><input id="lnk" value="'+lk+'" style="flex:1;padding:10px;border:1px solid var(--bd);border-radius:8px;background:var(--hv);color:var(--tx);font-weight:bold" readonly></div><div style="text-align:center"><button class="btn bp" onclick="cl()"><?=T('ok')?></button></div>';
    $('mok').style.display='none';
    navigator.clipboard.writeText(lk);
}
</script></body></html>
<?php } } ?>
