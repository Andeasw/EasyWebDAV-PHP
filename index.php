<?php
/**
 * EasyWebDAV - Single File WebDAV Server & File Manager
 * Optimized for UI/UX and Performance
 * By Prince 2025.11 | https://github.com/Andeasw/EasyWebDAV-PHP
 */
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
define('LOG_ENABLED', true);
define('LOG_PATH', __DIR__.'/logs');
@error_reporting(0);
@set_time_limit(0);
@ignore_user_abort(true);
date_default_timezone_set('PRC');
if(LOG_ENABLED && !file_exists(LOG_PATH)) @mkdir(LOG_PATH, 0755, true);
if(session_status()===PHP_SESSION_NONE) session_start();
if(empty($_SESSION['t'])) $_SESSION['t']=bin2hex(random_bytes(32));
$csrf=$_SESSION['t'];
define('ROOT',__DIR__);
define('S_NAME',basename($_SERVER['SCRIPT_NAME']));
$isIdx=S_NAME==='index.php';
$proto=(isset($_SERVER['HTTPS'])&&$_SERVER['HTTPS']==='on'?'https':'http');
$host=$_SERVER['HTTP_HOST'];
$uri=strtok($_SERVER['REQUEST_URI'],'?');
$baseUri=$isIdx?dirname($_SERVER['SCRIPT_NAME']):$_SERVER['SCRIPT_NAME'];
$baseUri=rtrim(str_replace('\\','/',$baseUri),'/');
define('BASE',$proto."://".$host.$baseUri);
define('S_PATH',ROOT.'/storage');
define('AUTH_F',ROOT.'/.htpasswd.php');
define('SHARE_F',ROOT.'/.shares.php');
define('DENY',['.','..','.htaccess','.htpasswd.php','.shares.php',S_NAME,basename(__FILE__)]);
if(!file_exists(S_PATH)) @mkdir(S_PATH,0755,true);
if(!file_exists(S_PATH.'/.htaccess')) @file_put_contents(S_PATH.'/.htaccess',"Deny from all");
if(!file_exists(ROOT.'/.htaccess')) @file_put_contents(ROOT.'/.htaccess',"Options -Indexes\nRewriteEngine On\nRewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]");
function log_action($action, $details='', $user='', $ip='', $status='success'){
    if(!LOG_ENABLED) return;
    $ip = $ip ?: ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
    $user = $user ?: ($_SERVER['PHP_AUTH_USER'] ?? 'unknown');
    $log_entry = sprintf("[%s] [%s] [%s] [%s] [%s] %s\n", date('Y-m-d H:i:s'), $user, $ip, strtoupper($status), $action, $details);
    @file_put_contents(LOG_PATH.'/'.date('Y-m-d').'.log', $log_entry, FILE_APPEND | LOCK_EX);
}
$pi=$_SERVER['PATH_INFO']??'';
$shareToken='';
if(preg_match('#^/s/([a-zA-Z0-9]+)#', $pi, $m)) $shareToken=$m[1];
elseif(isset($_GET['s'])) $shareToken=$_GET['s'];
if($shareToken && ctype_alnum($shareToken)){
    if(file_exists(SHARE_F)){
        $s=include SHARE_F;
        if(isset($s[$shareToken])&&is_array($s[$shareToken])&&file_exists($f=S_PATH.'/'.$s[$shareToken]['path'])){
            $share=$s[$shareToken];
            if($share['expires']>0&&time()>$share['expires']){
                http_response_code(410); die('Link expired (Time)');
            }
            if($share['max_uses']>0&&$share['uses']>=$share['max_uses']){
                http_response_code(410); die('Link expired (Max uses)');
            }
            $s[$shareToken]['uses']++;
            @file_put_contents(SHARE_F,"<?php\nreturn ".var_export($s,true).";",LOCK_EX);
            log_action('SHARE_ACCESS', 'Token: '.$shareToken.' Path: '.$share['path'].' Uses: '.$s[$shareToken]['uses']);
            $x=strtolower(pathinfo($f,4));
            $m=['txt'=>'text/plain','html'=>'text/html','css'=>'text/css','js'=>'application/javascript','json'=>'application/json','jpg'=>'image/jpeg','jpeg'=>'image/jpeg','png'=>'image/png','gif'=>'image/gif','mp4'=>'video/mp4','pdf'=>'application/pdf','zip'=>'application/zip'];
            header('Content-Type: '.($m[$x]??'application/octet-stream'));
            header('Content-Disposition: attachment; filename="'.basename($f).'"');
            header('Content-Length: '.filesize($f));
            readfile($f); exit;
        }
    }
    http_response_code(404); die('Invalid link');
}
if(!file_exists(AUTH_F)){
    if(!empty($_SERVER['PHP_AUTH_USER'])&&!empty($_SERVER['PHP_AUTH_PW'])){
        @file_put_contents(AUTH_F,"<?php\nreturn ".var_export(['u'=>$_SERVER['PHP_AUTH_USER'],'h'=>password_hash($_SERVER['PHP_AUTH_PW'],PASSWORD_DEFAULT)],true).";");
        log_action('INITIAL_SETUP', 'User: '.$_SERVER['PHP_AUTH_USER'], 'system');
    }else{
        header('WWW-Authenticate: Basic realm="Install"');
        header('HTTP/1.0 401 Unauthorized');
        die('Initial login with admin credentials.');
    }
}
$ac=include AUTH_F;
$u=$_SERVER['PHP_AUTH_USER']??'';
$p=$_SERVER['PHP_AUTH_PW']??'';
if($u!==$ac['u']||!password_verify($p,$ac['h'])){
    $h=$_SERVER['HTTP_AUTHORIZATION']??($_SERVER['REDIRECT_HTTP_AUTHORIZATION']??'');
    if($h&&preg_match('/Basic\s+(.*)$/i',$h,$m)) list($u,$p)=explode(':',base64_decode($m[1]),2);
    if($u!==$ac['u']||!password_verify($p,$ac['h'])){
        log_action('AUTH_FAILED', 'User: '.$u, $u, '', 'failed');
        header('WWW-Authenticate: Basic realm="EasyWebDAV"');
        header('HTTP/1.0 401 Unauthorized');
        die('Access Denied');
    }
}
log_action('LOGIN', 'User: '.$u, $u);
$lang=$_COOKIE['l']??'cn';
$L=['cn'=>['home'=>'首页','back'=>'返回上级','up'=>'上传','new'=>'新建文件夹','cr'=>'创建','nm'=>'名称','sz'=>'大小','tm'=>'修改时间','ac'=>'操作','dl'=>'下载','rn'=>'重命名','cp'=>'复制','mv'=>'移动','rm'=>'删除','sh'=>'分享','emp'=>'空目录','tip'=>'确认删除','lnk'=>'直链地址','cpl'=>'复制链接','ok'=>'确定','cc'=>'取消','tar'=>'目标路径','sh_m'=>'分享管理','sh_new'=>'新建分享','sh_up'=>'更新设置','sh_rnd'=>'随机生成','sh_cus'=>'自定义','sh_del'=>'取消分享','sh_ok'=>'链接已复制','exp'=>'有效期','uses'=>'使用情况','unlimited'=>'无限制','days'=>'天','hours'=>'小时','max_uses'=>'最大次数','set'=>'设置','link_copied'=>'链接已复制','exp_never'=>'永不过期','exp_1d'=>'1天','exp_7d'=>'7天','exp_30d'=>'30天','uses_1'=>'1次','uses_5'=>'5次','uses_10'=>'10次','uses_50'=>'50次','custom'=>'自定义','sharing'=>'分享设置','save'=>'保存','modify'=>'修改配置','log_title'=>'操作日志','log_download'=>'下载日志','log_clear'=>'清空日志','st_exp'=>'已过期','st_ok'=>'分享中','stat'=>'统计信息','exp_at'=>'到期时间','used'=>'已用'],'en'=>['home'=>'Home','back'=>'Back','up'=>'Upload','new'=>'New Folder','cr'=>'Create','nm'=>'Name','sz'=>'Size','tm'=>'Modified','ac'=>'Actions','dl'=>'Download','rn'=>'Rename','cp'=>'Copy','mv'=>'Move','rm'=>'Delete','sh'=>'Share','emp'=>'Empty','tip'=>'Confirm Delete','lnk'=>'Link','cpl'=>'Copy Link','ok'=>'OK','cc'=>'Cancel','tar'=>'Target Path','sh_m'=>'Share Manager','sh_new'=>'New Share','sh_up'=>'Update Settings','sh_rnd'=>'Random','sh_cus'=>'Custom','sh_del'=>'Unshare','sh_ok'=>'Link Copied','exp'=>'Expires In','uses'=>'Usage','unlimited'=>'Unlimited','days'=>'days','hours'=>'hours','max_uses'=>'Max Uses','set'=>'Settings','link_copied'=>'Link copied','exp_never'=>'Never','exp_1d'=>'1 day','exp_7d'=>'7 days','exp_30d'=>'30 days','uses_1'=>'1 use','uses_5'=>'5 uses','uses_10'=>'10 uses','uses_50'=>'50 uses','custom'=>'Custom','sharing'=>'Sharing Settings','save'=>'Save','modify'=>'Modify Share','log_title'=>'Operation Logs','log_download'=>'Download Log','log_clear'=>'Clear Log','st_exp'=>'EXPIRED','st_ok'=>'SHARED','stat'=>'Statistics','exp_at'=>'Expires At','used'=>'Used']];
if(isset($_GET['l'])){setcookie('l',$_GET['l'],time()+31536000);header("Location: ".BASE);exit;}
function T($k){global $L,$lang;return $L[$lang][$k]??$k;}
if(isset($_GET['log_action'])){
    if($_GET['log_action']==='download' && LOG_ENABLED){
        $log_file = LOG_PATH.'/'.date('Y-m-d').'.log';
        if(file_exists($log_file)){header('Content-Type: text/plain');header('Content-Disposition: attachment; filename="log-'.date('Y-m-d').'.txt"');readfile($log_file);exit;}
    }elseif($_GET['log_action']==='clear' && LOG_ENABLED){
        $log_file = LOG_PATH.'/'.date('Y-m-d').'.log';
        if(file_exists($log_file)){@file_put_contents($log_file, '');log_action('LOG_CLEAR', 'Logs cleared', $u);header("Location: ".BASE);exit;}
    }
}
$dav=new Dav();
if($_SERVER['REQUEST_METHOD']==='POST'){
    if(isset($_FILES['f'])||isset($_POST['md'])||isset($_POST['act'])||isset($_POST['s_act'])) $dav->handleBrowser();
    else $dav->serve();
}else $dav->serve();
class Dav{
    private $uri,$req,$path;
    public function __construct(){
        $this->uri=strtok($_SERVER['SCRIPT_NAME'],'?');
        $u=rawurldecode(explode('?',$_SERVER['REQUEST_URI'])[0]);
        $this->req=(strpos($u,$this->uri)===0)?substr($u,strlen($this->uri)):$u;
        $this->req=empty($this->req)?'/':rtrim($this->req,'/');
        $this->path=$this->cleanPath($this->req);
    }
    private function cleanPath($req){
        $parts=array_filter(explode('/',trim($req,'/')));
        $clean=[];
        foreach($parts as $part){if($part==='.'||$part==='..'||$this->isDenied($part)) continue;$clean[]=$part;}
        return S_PATH.($clean?'/'.implode('/',$clean):'');
    }
    private function chk(){if(!isset($_POST['t'])||!hash_equals($_SESSION['t'],$_POST['t']))die('CSRF');}
    private function isDenied($n){return in_array($n,DENY)||preg_match('/[\/\\\:\*\?"<>\|\x00-\x1F]/',$n);}
    private function back($q=''){header("Location: ".BASE.$q);exit;}
    private function cleanShare($p){
        if(!file_exists(SHARE_F)) return;
        $s=include SHARE_F;
        if(!is_array($s)) return;
        $rel=str_replace('\\','/',ltrim(substr($p,strlen(S_PATH)),'/\\'));
        $ch=false;
        foreach($s as $k=>$v){if(!is_array($v)) continue;if($v['path']===$rel||strpos($v['path'],$rel.'/')===0){unset($s[$k]);$ch=true;}}
        if($ch) @file_put_contents(SHARE_F,"<?php\nreturn ".var_export($s,true).";",LOCK_EX);
    }
    private function safeDel($p,$d=0){
        if($d>20||!file_exists($p)||strpos(realpath($p),realpath(S_PATH))!==0) return false;
        if(is_link($p)) return unlink($p);
        if(is_dir($p)){$it=@scandir($p);if($it===false) return false;foreach($it as $i){if($i==='.'||$i==='..')continue;$this->safeDel($p.'/'.$i,$d+1);}return @rmdir($p);}
        return @unlink($p);
    }
    private function safeCopy($s,$d,$dp=0){
        if($dp>20) return false;if(is_link($s)) return false;
        if(is_dir($s)){if(!file_exists($d)&&!@mkdir($d,0755,true)) return false;$it=@scandir($s);if($it===false) return false;$r=true;foreach($it as $i){if($i==='.'||$i==='..')continue;$r=$this->safeCopy($s.'/'.$i,$d.'/'.$i,$dp+1)&&$r;}return $r;}
        return @copy($s,$d);
    }
    public function serve(){
        try{
            switch($_SERVER['REQUEST_METHOD']){
                case 'GET': $this->GET(); break;
                case 'PUT': $this->PUT(); break;
                case 'DELETE': $this->DELETE(); break;
                case 'MKCOL': $this->MKCOL(); break;
                case 'PROPFIND': $this->PROP(); break;
                case 'COPY': $this->COPY(); break;
                case 'MOVE': $this->MOVE(); break;
                case 'LOCK': $this->LOCK(); break;
                case 'UNLOCK': $this->UNLOCK(); break;
                case 'OPTIONS': header('DAV: 1,2'); header('Allow: OPTIONS,GET,HEAD,DELETE,PROPFIND,PUT,MKCOL,COPY,MOVE,LOCK,UNLOCK'); exit;
                case 'HEAD': $this->HEAD(); break;
                default: http_response_code(405);
            }
        }catch(Exception $e){http_response_code(500);log_action('SERVER_ERROR', $e->getMessage(), $_SERVER['PHP_AUTH_USER']??'unknown', '', 'error');}
    }
    public function handleBrowser(){
        $this->chk();global $u;
        if(isset($_FILES['f'])&&$_FILES['f']['error']===UPLOAD_ERR_OK){
            $n=basename($_FILES['f']['name']);
            if(!$this->isDenied($n)){
                $target=$this->path.'/'.$n;
                if(move_uploaded_file($_FILES['f']['tmp_name'],$target)){@chmod($target,0644);log_action('UPLOAD', 'File: '.$n, $u);}
            }
        }elseif(isset($_POST['md'])&&($d=trim($_POST['md']))&&!$this->isDenied($d)){
            @mkdir($this->path.'/'.$d,0755,true);log_action('CREATE_DIR', 'Dir: '.$d, $u);
        }elseif(isset($_POST['act'])&&isset($_POST['n'])){
            $act=$_POST['act'];$n=basename($_POST['n']);if($this->isDenied($n)) return;$t=$this->path.'/'.$n;if(!file_exists($t)) return;
            if($act==='rn'&&($nn=trim($_POST['nn']??''))&&!$this->isDenied($nn)&&!file_exists(dirname($t).'/'.$nn)){
                $this->cleanShare($t);rename($t,dirname($t).'/'.$nn);log_action('RENAME', $n.'->'.$nn, $u);
            }elseif($act==='rm'){
                $this->cleanShare($t);$this->safeDel($t);log_action('DELETE', $n, $u);
            }elseif(($act==='cp'||$act==='mv')&&($tg=$_POST['tg']??'')){
                $dst=$this->cleanPath('/'.ltrim($tg,'/')).'/'.$n;
                if(!$this->isDenied(basename($dst))){
                    if($act==='mv'){$this->cleanShare($t);if(!is_dir(dirname($dst))) @mkdir(dirname($dst),0755,true);rename($t,$dst);log_action('MOVE', $n.' to '.$tg, $u);}
                    else{if(!is_dir(dirname($dst))) @mkdir(dirname($dst),0755,true);$this->safeCopy($t,$dst);log_action('COPY', $n.' to '.$tg, $u);}
                }
            }
        }elseif(isset($_POST['s_act'])){
            $sa=$_POST['s_act'];$n=basename($_POST['n']??'');$rel=str_replace('\\','/',ltrim(substr($this->path.'/'.$n,strlen(S_PATH)),'/\\'));
            $s=file_exists(SHARE_F)?include SHARE_F:[];if(!is_array($s))$s=[];
            if($sa==='c_quick'){
                do{$tok=bin2hex(random_bytes(16));}while(isset($s[$tok]));
                $s[$tok]=['path'=>$rel,'created'=>time(),'expires'=>0,'max_uses'=>0,'uses'=>0];
                @file_put_contents(SHARE_F,"<?php\nreturn ".var_export($s,true).";",LOCK_EX);
                log_action('SHARE_QUICK', 'File: '.$n.' Token: '.$tok, $u);
                $this->back('?quick='.$tok);
            }elseif($sa==='c'||$sa==='u'){
                $ot=$_POST['otok']??'';$nt=trim($_POST['ntok']??'');$max=$_POST['max']??0;
                if($sa==='u'&&isset($s[$ot])) unset($s[$ot]);
                if(empty($nt)||!ctype_alnum($nt)||strlen($nt)>128||strlen($nt)<8) $nt=bin2hex(random_bytes(16));
                if($_POST['exp']==='custom'){
                    $v=intval($_POST['exp_custom']??0);$u_exp=$_POST['exp_unit']??'days';
                    $sec=$v*($u_exp==='days'?86400:3600);
                    $exp=$sec>0?time()+$sec:0;
                }else{
                    $v=intval($_POST['exp']);
                    $exp=$v>0?time()+$v:0;
                }
                $s[$nt]=['path'=>$rel,'created'=>time(),'expires'=>$exp,'max_uses'=>intval($max),'uses'=>0];
                if($sa==='u'&&isset($_POST['cur_uses'])) $s[$nt]['uses']=intval($_POST['cur_uses']);
                @file_put_contents(SHARE_F,"<?php\nreturn ".var_export($s,true).";",LOCK_EX);
                log_action($sa==='c'?'SHARE_CREATE':'SHARE_UPDATE', 'File: '.$n.' Token: '.$nt, $u);
                $this->back();
            }elseif($sa==='d'){
                $ot=$_POST['otok']??'';if(isset($s[$ot])) unset($s[$ot]);
                @file_put_contents(SHARE_F,"<?php\nreturn ".var_export($s,true).";",LOCK_EX);
                log_action('SHARE_DELETE', 'Token: '.$ot, $u);
            }
        }
        $this->back();
    }
    private function GET(){
        if(!file_exists($this->path)){http_response_code(404);exit;}
        if(is_dir($this->path)){$this->HTML();exit;}
        if($this->isDenied(basename($this->path))){http_response_code(403);exit;}
        $dl=isset($_GET['dl']);$m=$this->mime($this->path);
        header('Content-Type: '.($dl?'application/octet-stream':$m));header('Content-Length: '.filesize($this->path));header('ETag: "'.hash_file('md5',$this->path).'"');
        header('Content-Disposition: '.($dl?'attachment':'inline').'; filename="'.basename($this->path).'"');
        log_action('FILE_ACCESS', 'File: '.basename($this->path), $_SERVER['PHP_AUTH_USER']??'unknown');
        if($dl||strpos($m,'text/')!==0) readfile($this->path);
        else{header('Content-Security-Policy: default-src \'none\'');echo htmlspecialchars(file_get_contents($this->path),ENT_QUOTES,'UTF-8');}exit;
    }
    private function PUT(){
        global $u;if($this->isDenied(basename($this->path))){http_response_code(403);exit;}
        if(!is_dir(dirname($this->path))) mkdir(dirname($this->path),0755,true);
        $i=fopen('php://input','r');$o=fopen($this->path,'w');
        if($i&&$o){stream_copy_to_stream($i,$o);fclose($i);fclose($o);log_action('WEBDAV_PUT', basename($this->path), $u);http_response_code(201);}else http_response_code(500);
    }
    private function DELETE(){
        global $u;if(file_exists($this->path)&&$this->path!==S_PATH){$this->cleanShare($this->path);if($this->safeDel($this->path)){log_action('WEBDAV_DELETE', $this->req, $u);http_response_code(204);}else http_response_code(500);}else http_response_code(403);
    }
    private function MKCOL(){
        global $u;if(file_exists($this->path)){http_response_code(405);exit;}if(!is_dir(dirname($this->path))) mkdir(dirname($this->path),0755,true);
        if(mkdir($this->path,0755,true)){log_action('WEBDAV_MKCOL', $this->req, $u);http_response_code(201);}else http_response_code(409);
    }
    private function PROP(){
        if(!file_exists($this->path)){http_response_code(404);exit;}
        header('HTTP/1.1 207 Multi-Status');header('Content-Type: application/xml; charset="utf-8"');
        $depth=$_SERVER['HTTP_DEPTH']??'1';if($depth==='infinity'){http_response_code(403);exit;}
        echo '<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">';
        $items=[$this->path];if($depth!=='0'&&is_dir($this->path)){$items=array_merge($items,glob($this->path.'/*'));}
        foreach($items as $f){
            if(!file_exists($f)||$this->isDenied(basename($f))) continue;
            $rel=str_replace('\\','/',substr($f,strlen(S_PATH)));$href=$this->uri.($rel===''?'/':str_replace('%2F','/',rawurlencode($rel)));
            echo '<D:response><D:href>'.htmlspecialchars($href,ENT_XML1).'</D:href><D:propstat><D:prop>';
            echo '<D:displayname>'.htmlspecialchars(basename($f),ENT_XML1).'</D:displayname>';
            echo '<D:getlastmodified>'.gmdate('D, d M Y H:i:s T',filemtime($f)).'</D:getlastmodified>';
            echo '<D:getetag>"'.hash_file('md5',$f).'"</D:getetag>';echo '<D:creationdate>'.gmdate('Y-m-d\\TH:i:s\\Z',filectime($f)).'</D:creationdate>';
            if(is_dir($f)){echo '<D:resourcetype><D:collection/></D:resourcetype>';echo '<D:getcontentlength/>';}else{echo '<D:resourcetype/>';echo '<D:getcontentlength>'.filesize($f).'</D:getcontentlength>';echo '<D:getcontenttype>'.$this->mime($f).'</D:getcontenttype>';}
            echo '<D:supportedlock><D:lockentry><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockentry><D:lockentry><D:lockscope><D:shared/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockentry></D:supportedlock>';
            echo '<D:lockdiscovery/>';echo '</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>';
        }echo '</D:multistatus>';
    }
    private function COPY(){ $this->copyMove(false); }
    private function MOVE(){ $this->copyMove(true); }
    private function copyMove($mv){
        global $u;$d=$_SERVER['HTTP_DESTINATION']??'';if(empty($d)){http_response_code(400);exit;}
        $dp=rawurldecode(parse_url($d,PHP_URL_PATH));if(strpos($dp,$this->uri)!==0){http_response_code(502);exit;}
        $rd=substr($dp,strpos($dp,$this->uri)+strlen($this->uri));$parts=array_filter(explode('/',trim($rd,'/')),function($p){return $p!==''&&$p!=='.'&&$p!=='..'&&!$this->isDenied($p);});
        $dst=S_PATH.'/'.implode('/',$parts);if($this->isDenied(basename($dst))){http_response_code(403);exit;}
        if(!is_dir(dirname($dst))) mkdir(dirname($dst),0755,true);if(file_exists($dst)){if(($_SERVER['HTTP_OVERWRITE']??'T')==='F'){http_response_code(412);exit;}$this->safeDel($dst);}
        if($mv){$this->cleanShare($this->path);if(!rename($this->path,$dst)){if($this->safeCopy($this->path,$dst)){$this->safeDel($this->path);}else{http_response_code(500);exit;}}log_action('WEBDAV_MOVE', $this->req.'->'.$rd, $u);http_response_code(201);}
        else{if($this->safeCopy($this->path,$dst)){log_action('WEBDAV_COPY', $this->req.'->'.$rd, $u);http_response_code(201);}else http_response_code(500);}
    }
    private function LOCK(){header('Content-Type: application/xml; charset="utf-8"');$lock=$this->path.'.lock';if(file_exists($lock)){$time=@file_get_contents($lock);if($time&&time()-$time<3600){http_response_code(423); exit;}}@file_put_contents($lock,time());http_response_code(200);echo '<?xml version="1.0" encoding="utf-8"?><D:prop xmlns:D="DAV:"><D:lockdiscovery/></D:prop>';}
    private function UNLOCK(){@unlink($this->path.'.lock');http_response_code(204);}
    private function HEAD(){
        if(!file_exists($this->path)){http_response_code(404);exit;}if($this->isDenied(basename($this->path))){http_response_code(403);exit;}
        header('Content-Type: '.$this->mime($this->path));header('Content-Length: '.filesize($this->path));header('ETag: "'.hash_file('md5',$this->path).'"');
        if(isset($_SERVER['HTTP_RANGE'])){http_response_code(206);$size=filesize($this->path);list($start,$end)=explode('-',substr($_SERVER['HTTP_RANGE'],6));$start=intval($start);$end=$end?min(intval($end),$size-1):$size-1;header("Content-Range: bytes $start-$end/$size");}
    }
    private function mime($f){$x=strtolower(pathinfo($f,4));$m=['txt'=>'text/plain','html'=>'text/html','css'=>'text/css','js'=>'application/javascript','json'=>'application/json','jpg'=>'image/jpeg','jpeg'=>'image/jpeg','png'=>'image/png','gif'=>'image/gif','mp4'=>'video/mp4','pdf'=>'application/pdf','zip'=>'application/zip'];return $m[$x]??'application/octet-stream';}
    private function size($b){$u=['B','KB','MB','GB'];$i=0;while($b>=1024&&$i<3){$b/=1024;$i++;}return round($b,2).' '.$u[$i];}
    private function HTML(){
        global $csrf,$lang;$l=@scandir($this->path);if($l===false) $l=[];
        usort($l,function($a,$b){$ad=is_dir($this->path.'/'.$a);$bd=is_dir($this->path.'/'.$b);return $ad===$bd?strcasecmp($a,$b):($ad?-1:1);});
        $bc=[];$acc='';foreach(array_filter(explode('/',$this->req))as $p){$acc.='/'.$p;$bc[]=['n'=>$p,'u'=>$this->uri.implode('/',array_map('rawurlencode',explode('/',$acc)))];}
        $sh=file_exists(SHARE_F)?include SHARE_F:[];$sm=[];if(is_array($sh))foreach($sh as $k=>$v)if(is_array($v))$sm[$v['path']]=$k;
        $quickS=$_GET['quick']??'';
        $I=['f'=>'<svg class="i" viewBox="0 0 24 24"><path fill="currentColor" d="M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6z"/></svg>','d'=>'<svg class="i" viewBox="0 0 24 24" style="color:#facc15"><path fill="currentColor" d="M10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>','dl'=>'<svg viewBox="0 0 24 24"><path fill="currentColor" d="M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z"/></svg>','sh'=>'<svg viewBox="0 0 24 24"><path fill="currentColor" d="M18 16.08c-.76 0-1.44.3-1.96.77L8.91 12.7c.05-.23.09-.46.09-.7s-.04-.47-.09-.7l7.05-4.11c.54.5 1.25.81 2.04.81 1.66 0 3-1.34 3-3s-1.34-3-3-3-3 1.34-3 3c0 .24.04.47.09.7L8.04 9.81C7.5 9.31 6.79 9 6 9c-1.66 0-3 1.34-3 3s1.34 3 3 3c.79 0 1.5-.31 2.04-.81l7.12 4.16c-.05.21-.08.43-.08.65 0 1.61 1.31 2.92 2.92 2.92 1.61 0 2.92-1.31 2.92-2.92s-1.31-2.92-2.92-2.92z"/></svg>','ed'=>'<svg viewBox="0 0 24 24"><path fill="currentColor" d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>','cp'=>'<svg viewBox="0 0 24 24"><path fill="currentColor" d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>','mv'=>'<svg viewBox="0 0 24 24"><path fill="currentColor" d="M10 9h4V6h3l-5-5-5 5h3v3zm-1 1H6V7l-5 5 5 5v-3h3v-4zm14 2l-5-5v3h-3v4h3v3l5-5zm-9 3h-4v3H7l5 5 5-5h-3v-3z"/></svg>','rm'=>'<svg viewBox="0 0 24 24"><path fill="currentColor" d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>','log'=>'<svg viewBox="0 0 24 24"><path fill="currentColor" d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-5 14H7v-2h7v2zm3-4H7v-2h10v2zm0-4H7V7h10v2z"/></svg>'];
?><!DOCTYPE html><html lang="<?=$lang?>"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>EasyWebDAV</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;charset=utf-8,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64' width='64' height='64'%3E%3Cdefs%3E%3ClinearGradient id='a' x1='0' y1='0' x2='1' y2='1'%3E%3Cstop offset='0%25' stop-color='%2364B5F6'/%3E%3Cstop offset='100%25' stop-color='%232196F3'/%3E%3C/linearGradient%3E%3C/defs%3E%3Cpath fill='url(%23a)' d='M18 46h28c7 0 12-5.5 12-12 0-6-4.3-10.8-10.2-11.7C45.5 15 39.3 11 32 11s-13.5 4-15.8 11.3C10.3 23.2 6 28 6 34c0 6.5 5 12 12 12z'/%3E%3C/svg%3E">
<style>
:root{--bg-g:linear-gradient(135deg, #e0f7fa 0%, #fce4ec 100%);--bg:rgba(255,255,255,0.94);--tx:#263238;--bd:#cfd8dc;--hv:#f5f7fa;--p:#5c6bc0;--pd:#3949ab;--ac:#26a69a;--er:#ef5350;--sh:0 12px 32px -8px rgba(0,0,0,0.08);}
.dark{--bg-g:linear-gradient(135deg, #1a237e 0%, #311b92 100%);--bg:rgba(30,30,40,0.96);--tx:#eceff1;--bd:#455a64;--hv:#263238;--p:#7986cb;--pd:#5c6bc0;--ac:#4db6ac;--er:#e57373;--sh:0 12px 32px -8px rgba(0,0,0,0.4);}
body{margin:0;font-family:'Segoe UI',system-ui,-apple-system,BlinkMacSystemFont,Roboto,'Helvetica Neue',Arial,sans-serif;background:var(--bg-g);color:var(--tx);min-height:100vh;background-attachment:fixed;display:flex;justify-content:center;align-items:start;padding-top:30px;box-sizing:border-box;line-height:1.6}
.box{width:96%;max-width:1120px;min-height:85vh;background:var(--bg);border-radius:20px;box-shadow:var(--sh);border:1px solid var(--bd);display:flex;flex-direction:column;overflow:hidden;backdrop-filter:blur(20px);transition:all 0.3s cubic-bezier(0.4,0,0.2,1)}
header{padding:20px 28px;border-bottom:1px solid var(--bd);display:flex;justify-content:space-between;align-items:center;background:rgba(255,255,255,0.4);flex-shrink:0;backdrop-filter:blur(12px)}
.dark header{background:rgba(30,30,40,0.4)}
.nav a{text-decoration:none;color:var(--tx);padding:8px 14px;border-radius:10px;transition:all 0.2s ease;font-weight:500;font-size:15px;margin:0 2px}
.nav a:hover{background:var(--p);color:#fff;transform:translateY(-1px);box-shadow:0 4px 12px rgba(92,107,192,0.3)}
.bar{padding:16px 28px;background:var(--hv);border-bottom:1px solid var(--bd);display:flex;gap:12px;align-items:center;flex-wrap:wrap;flex-shrink:0}
.btn{padding:10px 18px;border:2px solid var(--bd);background:#fff;border-radius:10px;cursor:pointer;font-size:14px;color:var(--tx);text-decoration:none;display:inline-flex;align-items:center;gap:8px;transition:all 0.2s ease;font-weight:600;box-shadow:0 2px 4px rgba(0,0,0,0.04)}
.dark .btn{background:#2c2c3c}
.btn:hover{border-color:var(--p);color:var(--p);transform:translateY(-2px);box-shadow:0 6px 16px rgba(0,0,0,0.12)}
.bp{background:var(--p);color:#fff;border:none}
.bp:hover{background:var(--pd);color:#fff;transform:translateY(-2px);box-shadow:0 6px 20px rgba(92,107,192,0.4)}
.bd{color:var(--er);border-color:transparent}
.bd:hover{background:var(--er);color:#fff}
.main{flex:1;overflow-x:auto;display:flex;flex-direction:column}
table{width:100%;border-collapse:collapse;min-width:680px}
th{text-align:left;padding:18px 28px;color:var(--pd);font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:0.8px;border-bottom:2px solid var(--bd);background:rgba(92,107,192,0.08);position:sticky;top:0}
td{padding:16px 28px;border-bottom:1px solid var(--bd);font-size:15px;vertical-align:middle;transition:background 0.2s}
tr:hover td{background:var(--hv)}
.lnk{text-decoration:none;color:var(--tx);display:flex;align-items:center;gap:12px;font-weight:500;transition:all 0.2s}
.lnk:hover{color:var(--p)}
.i{width:24px;height:24px;color:#78909c}
.acts{display:flex;gap:8px;justify-content:flex-end}
.ab{padding:8px;border:none;background:0 0;cursor:pointer;color:#78909c;border-radius:10px;display:flex;transition:all 0.2s}
.ab:hover{background:#e8eaf6;color:var(--p);transform:translateY(-1px)}
.dark .ab:hover{background:rgba(121,134,203,0.2)}
.ab svg{width:18px;height:18px}
.ab.del:hover{background:#ffebee;color:var(--er)}
.mod{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.25);z-index:99;justify-content:center;align-items:center;backdrop-filter:blur(8px);animation:fadeIn 0.3s ease}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
.mb{background:#fff;padding:32px;border-radius:24px;width:92%;max-width:500px;box-shadow:0 32px 64px -16px rgba(0,0,0,0.2);border:1px solid var(--bd);animation:slideUp 0.3s ease}
@keyframes slideUp{from{transform:translateY(20px);opacity:0}to{transform:translateY(0);opacity:1}}
.dark .mb{background:#2c2c3c}
.ft{padding:24px;text-align:center;font-size:14px;color:#78909c;background:var(--hv);border-top:1px solid var(--bd);display:flex;justify-content:center;align-items:center;gap:10px;flex-shrink:0}
.gh svg{width:20px;height:20px;fill:#78909c;transition:fill 0.2s}
.gh:hover svg{fill:var(--p)}
.tg{background:0 0;border:none;cursor:pointer;padding:8px;border-radius:50%;color:var(--tx);transition:all 0.2s}
.tg:hover{background:rgba(0,0,0,0.08)}
.float-icon{animation:flt 3s ease-in-out infinite,shn 4s ease-in-out infinite;display:block}
@keyframes flt{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}
@keyframes shn{0%,100%{filter:drop-shadow(0 0 3px rgba(253,184,19,0.5))}50%{filter:drop-shadow(0 0 12px rgba(253,184,19,0.9))}}
@media(max-width:768px){body{padding:0;display:block}.box{margin:0;width:100%;max-width:none;border:none;border-radius:0;min-height:100vh}.hm{display:none}.mb{padding:24px;width:95%}}
.form-group{margin-bottom:20px}
.form-label{display:block;margin-bottom:8px;font-size:14px;color:var(--pd);font-weight:600}
.form-input,.form-select{width:100%;padding:12px 16px;border:2px solid var(--bd);border-radius:10px;background:rgba(255,255,255,0.8);color:var(--tx);font-size:15px;transition:all 0.2s;box-sizing:border-box}
.dark .form-input,.dark .form-select{background:rgba(40,40,50,0.8)}
.form-input:focus,.form-select:focus{outline:none;border-color:var(--p);box-shadow:0 0 0 4px rgba(92,107,192,0.15)}
.form-row{display:flex;gap:12px;align-items:center;margin-top:8px}
.form-row .form-input{flex:1}
.custom-options{display:none;margin-top:12px;padding:16px;background:rgba(0,0,0,0.04);border-radius:10px;animation:fadeIn 0.3s ease}
.dark .custom-options{background:rgba(255,255,255,0.06)}
.link-display{background:rgba(0,0,0,0.04);padding:16px;border-radius:10px;margin-bottom:24px}
.dark .link-display{background:rgba(255,255,255,0.06)}
.link-display input{width:100%;padding:10px 12px;border:2px solid var(--bd);border-radius:8px;background:rgba(255,255,255,0.8);color:var(--tx);font-size:14px;box-sizing:border-box}
.dark .link-display input{background:rgba(40,40,50,0.8)}
.stat-box{padding:12px;background:rgba(92,107,192,0.08);border-radius:8px;margin-bottom:20px;font-size:13px;color:var(--tx);border:1px solid var(--bd)}
.toast{position:fixed;bottom:24px;right:24px;background:var(--p);color:#fff;padding:16px 24px;border-radius:12px;box-shadow:0 8px 24px rgba(0,0,0,0.2);display:flex;align-items:center;gap:12px;animation:slideIn 0.3s ease;z-index:100;max-width:400px}
@keyframes slideIn{from{transform:translateX(100%);opacity:0}to{transform:translateX(0);opacity:1}}
.toast-close{background:none;border:none;color:#fff;cursor:pointer;font-size:20px;line-height:1;padding:4px;opacity:0.8}
.toast-close:hover{opacity:1}
.badge{font-size:10px;padding:3px 8px;border-radius:5px;font-weight:600;margin-left:8px;display:inline-block}
.badge.ok{color:var(--ac);background:rgba(38,166,154,.12)}
.badge.exp{color:var(--er);background:rgba(239,83,80,.12)}
</style></head><body class="<?=$_COOKIE['dk']??''?>"><div class="box">
<header>
    <div class="nav"><a href="<?=$this->uri?>/"><?=T('home')?></a><?php foreach($bc as $b) echo ' / <a href="'.$b['u'].'">'.htmlspecialchars($b['n']).'</a>';?></div>
    <div style="display:flex;gap:14px;align-items:center">
        <?php if(LOG_ENABLED): ?><a href="#" onclick="showLogs()" class="ab" title="<?=T('log_title')?>" style="padding:8px"><?=$I['log']?></a><?php endif; ?>
        <button class="tg" onclick="mode()"><svg class="float-icon" width="24" height="24" viewBox="0 0 24 24" fill="#FDB813"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg></button>
        <div style="font-size:13px;font-weight:600"><a href="?l=cn" style="text-decoration:none;color:<?=$lang=='cn'?'var(--p)':'#78909c'?>">CN</a> <span style="color:#cfd8dc">|</span> <a href="?l=en" style="text-decoration:none;color:<?=$lang=='en'?'var(--p)':'#78909c'?>">EN</a></div>
    </div>
</header>
<div class="bar">
    <?php if($this->req!=='/'): $pp=array_filter(explode('/',$this->req)); array_pop($pp); ?>
    <a href="<?=$this->uri.'/'.implode('/',array_map('rawurlencode',$pp))?>" class="btn"><?=T('back')?></a>
    <?php endif;?>
    <form method="post" enctype="multipart/form-data" style="margin:0"><input type="hidden" name="t" value="<?=$csrf?>"><label class="btn bp"><?=T('up')?><input type="file" name="f" hidden onchange="this.form.submit()"></label></form>
    <form method="post" style="display:flex;gap:10px;margin:0;flex:1"><input type="hidden" name="t" value="<?=$csrf?>"><input name="md" placeholder="<?=T('new')?>" required style="padding:10px 14px;border:2px solid var(--bd);border-radius:10px;outline:none;background:rgba(255,255,255,0.8);color:var(--tx);flex:1;min-width:120px;max-width:280px"><button class="btn"><?=T('cr')?></button></form>
</div>
<div class="main">
    <table>
        <thead><tr><th><?=T('nm')?></th><th class="hm"><?=T('sz')?></th><th class="hm"><?=T('tm')?></th><th style="text-align:right"><?=T('ac')?></th></tr></thead>
        <tbody>
            <?php if(count($l)<=2): ?><tr><td colspan="4" style="text-align:center;padding:80px 20px;color:#78909c;font-style:italic;font-size:16px"><?=T('emp')?></td></tr>
            <?php else: foreach($l as $f): if($this->isDenied($f))continue; $p=$this->path.'/'.$f; $d=is_dir($p); $lk=$this->uri.rtrim($this->req,'/').'/'.rawurlencode($f); $rp=str_replace('\\','/',ltrim(substr($p,strlen(S_PATH)),'/\\')); $shr=isset($sm[$rp])?$sh[$sm[$rp]]:null; 
            $sTok=$shr?$sm[$rp]:''; $isExp=false; if($shr){$isExp=($shr['expires']>0&&time()>$shr['expires'])||($shr['max_uses']>0&&$shr['uses']>=$shr['max_uses']);} ?>
            <tr>
                <td><a href="<?=$lk?>" class="lnk" target="<?=$d?'_self':'_blank'?>"><?=$d?$I['d']:$I['f']?><?=htmlspecialchars($f)?><?php if($shr): ?><span class="badge <?=$isExp?'exp':'ok'?>"><?=$isExp?T('st_exp'):T('st_ok')?></span><?php endif; ?></a></td>
                <td class="hm"><?=$d?'-':$this->size(filesize($p))?></td><td class="hm"><?=date('Y-m-d H:i',filemtime($p))?></td>
                <td><div class="acts">
                    <?php if(!$d): ?><a href="<?=$lk?>?dl=1" class="ab" title="<?=T('dl')?>"><?=$I['dl']?></a><button onclick="shareFile('<?=addslashes($f)?>','<?=$sTok?>',<?=$shr?$shr['expires']:0?>,<?=$shr?$shr['max_uses']:0?>,<?=$shr?$shr['uses']:0?>)" class="ab" title="<?=T('sh')?>"><?=$I['sh']?></button><?php endif; ?>
                    <button onclick="p('rn','<?=$f?>')" class="ab" title="<?=T('rn')?>"><?=$I['ed']?></button><button onclick="p('cp','<?=$f?>')" class="ab" title="<?=T('cp')?>"><?=$I['cp']?></button><button onclick="p('mv','<?=$f?>')" class="ab" title="<?=T('mv')?>"><?=$I['mv']?></button><button onclick="p('rm','<?=$f?>')" class="ab del" title="<?=T('rm')?>"><?=$I['rm']?></button>
                </div></td>
            </tr>
            <?php endforeach; endif; ?>
        </tbody>
    </table>
</div>
<div class="ft">&copy; <?=date('Y')?> EasyWebDAV-PHP</div>
</div>
<div id="md" class="mod"><div class="mb"><h3 id="mt" style="margin-top:0"></h3><div id="mc"></div><div style="margin-top:24px;text-align:right;display:flex;justify-content:flex-end;gap:12px"><button class="btn" onclick="cl()"><?=T('cc')?></button><button class="btn bp" id="mok"><?=T('ok')?></button></div></div></div>
<?php if(LOG_ENABLED): ?><div id="logModal" class="mod" style="display:none"><div class="mb" style="max-width:800px"><h3 style="margin-top:0;display:flex;justify-content:space-between;align-items:center"><span><?=T('log_title')?></span><div style="display:flex;gap:8px"><a href="?log_action=download" class="btn" style="font-size:13px"><?=T('log_download')?></a><a href="?log_action=clear" class="btn bd" style="font-size:13px" onclick="return confirm('Clear logs?')"><?=T('log_clear')?></a><button class="btn" onclick="cl()"><?=T('cc')?></button></div></h3><div style="max-height:400px;overflow-y:auto;background:rgba(0,0,0,0.03);border-radius:10px;padding:16px;margin-top:16px"><pre style="margin:0;font-size:12px;line-height:1.5;color:var(--tx)"><?php if(LOG_ENABLED){$log_file=LOG_PATH.'/'.date('Y-m-d').'.log';echo htmlspecialchars(file_exists($log_file)?file_get_contents($log_file):'No logs today.');} ?></pre></div></div></div><?php endif; ?>
<input id="q_lnk" value="<?=BASE.'/s/'.$quickS.'/'.basename($s[$quickS]['path']??'file')?>" hidden>
<script>
const $=i=>document.getElementById(i), csrf='<?=$csrf?>', cur='<?=$this->req==='/'?'':$this->req?>', quick='<?=$quickS?>', base='<?=BASE?>';
function showToast(msg){const t=document.createElement('div');t.className='toast';t.innerHTML=`<div style="flex:1">${msg}</div><button class="toast-close" onclick="this.parentElement.remove()">&times;</button>`;document.body.appendChild(t);setTimeout(()=>t.remove(),3000);}
function mode(){document.body.classList.toggle('dark');document.cookie='dk='+(document.body.classList.contains('dark')?'dark':'')+';path=/;max-age=31536000';}
function showLogs(){if($('logModal')) $('logModal').style.display='flex';}
function cl(){$('md').style.display='none';if($('logModal')) $('logModal').style.display='none';}
function pf(h){const f=document.createElement('form');f.style.display='none';f.method='post';f.innerHTML=h;document.body.appendChild(f);f.submit();}
function p(a,n){
    $('md').style.display='flex';$('mt').innerText=(a=='rn'?'<?=T('rn')?>':(a=='cp'?'<?=T('cp')?>':(a=='mv'?'<?=T('mv')?>':'<?=T('rm')?>')));
    let h='';if(a=='rm') h='<p><?=T('tip')?> "'+n+'"?</p>';
    else h='<input id="iv" value="'+(a=='rn'?n:cur)+'" style="width:100%;padding:12px 16px;border:2px solid var(--bd);border-radius:10px;background:rgba(255,255,255,0.8);color:var(--tx);box-sizing:border-box" placeholder="'+(a=='rn'?'<?=T('nm')?>':'<?=T('tar')?>')+'">';
    $('mc').innerHTML=h;if($('iv')) setTimeout(()=>$('iv').focus(),50);
    $('mok').className='btn '+(a=='rm'?'bd':'bp');$('mok').innerText=a=='rm'?'<?=T('rm')?>':'<?=T('ok')?>';$('mok').style.display='inline-flex';
    $('mok').onclick=()=>{let val=$('iv')?$('iv').value:'';pf('<input type="hidden" name="t" value="'+csrf+'"><input name="act" value="'+a+'"><input name="n" value="'+n.replace(/"/g,'&quot;')+'"><input name="'+(a=='rn'?'nn':'tg')+'" value="'+val.replace(/"/g,'&quot;')+'">');}
}
function shareFile(n,t,expAt,maxUses,curUses){
    if(!t){pf('<input type="hidden" name="t" value="'+csrf+'"><input name="s_act" value="c_quick"><input name="n" value="'+n.replace(/"/g,'&quot;')+'">');return;}
    $('md').style.display='flex';$('mt').innerText=t?'<?=T('modify')?>':'<?=T('sharing')?>';
    let lk=t?base+'/s/'+t+'/'+encodeURIComponent(n):'';
    let h='<div class="link-display"><div class="form-label"><?=T('lnk')?></div><div class="form-row"><input id="lnk" value="'+lk+'" readonly><button class="btn" onclick="copyLink(\'lnk\')"><?=T('cpl')?></button></div></div>';
    if(t){
        h+=`<div class="stat-box"><strong><?=T('stat')?></strong><br>${expAt>0?'<?=T('exp_at')?>: '+new Date(expAt*1000).toLocaleString():'<?=T('exp_never')?>'}<br><?=T('uses')?>: ${curUses} / ${maxUses==0?'∞':maxUses}</div>`;
    }
    h+='<div style="border-top:1px solid var(--bd);padding-top:20px">';
    h+=`<div class="form-group"><label class="form-label"><?=T('exp')?></label><select id="exp" class="form-select"><option value="0"><?=T('exp_never')?></option><option value="86400"><?=T('exp_1d')?></option><option value="604800"><?=T('exp_7d')?></option><option value="2592000"><?=T('exp_30d')?></option><option value="custom"><?=T('custom')?></option></select><div id="custExp" class="custom-options"><div class="form-row"><input id="expVal" type="number" min="1" value="7" class="form-input" placeholder="Value"><select id="expUnit" class="form-select" style="width:120px"><option value="days"><?=T('days')?></option><option value="hours"><?=T('hours')?></option></select></div></div></div><div class="form-group"><label class="form-label"><?=T('max_uses')?></label><select id="max" class="form-select"><option value="0"><?=T('unlimited')?></option><option value="1"><?=T('uses_1')?></option><option value="5"><?=T('uses_5')?></option><option value="10"><?=T('uses_10')?></option><option value="50"><?=T('uses_50')?></option><option value="custom"><?=T('custom')?></option></select><div id="custMax" class="custom-options"><input id="maxVal" type="number" min="1" value="10" class="form-input" placeholder="Count"></div></div><div class="form-group"><label class="form-label"><?=T('sh_cus')?></label><input id="ctok" class="form-input" placeholder="<?=T('sh_cus')?>" value="${t}"></div></div>`;
    $('mc').innerHTML=h;$('mok').style.display='none';
    if(t){
        let stdExps=[0,86400,604800,2592000], now=Math.floor(Date.now()/1000), diff=expAt>0?expAt-now:0;
        if(stdExps.includes(diff)||expAt===0) $('exp').value=expAt===0?0:diff;
        else{$('exp').value='custom';$('custExp').style.display='block';$('expVal').value=Math.ceil(diff/86400);}
        let stdMax=[0,1,5,10,50];
        if(stdMax.includes(maxUses)) $('max').value=maxUses;
        else{$('max').value='custom';$('custMax').style.display='block';$('maxVal').value=maxUses;}
    }
    const saveBtn=document.createElement('button');saveBtn.className='btn bp';saveBtn.style.width='100%';saveBtn.innerText='<?=T('save')?>';
    saveBtn.onclick=()=>{
        let exp=$('exp').value,max=$('max').value,tok=$('ctok').value.trim();
        let exp_custom=$('expVal')?$('expVal').value:7,exp_unit=$('expUnit')?$('expUnit').value:'days';
        let max_custom=$('maxVal')?$('maxVal').value:10;
        pf('<input type="hidden" name="t" value="'+csrf+'"><input name="s_act" value="u"><input name="n" value="'+n.replace(/"/g,'&quot;')+'"><input name="ntok" value="'+tok.replace(/"/g,'&quot;')+'"><input name="otok" value="'+t.replace(/"/g,'&quot;')+'"><input name="exp" value="'+exp+'"><input name="max" value="'+max+'"><input name="exp_custom" value="'+exp_custom+'"><input name="exp_unit" value="'+exp_unit+'"><input name="max_custom" value="'+max_custom+'"><input name="cur_uses" value="'+curUses+'">');
    };
    $('mc').appendChild(saveBtn);
    if(t){
        const delBtn=document.createElement('button');delBtn.className='btn bd';delBtn.style.width='100%';delBtn.style.marginTop='12px';delBtn.innerText='<?=T('sh_del')?>';
        delBtn.onclick=()=>{if(confirm('<?=T('tip')?>')) pf('<input type="hidden" name="t" value="'+csrf+'"><input name="s_act" value="d"><input name="n" value="'+n.replace(/"/g,'&quot;')+'"><input name="otok" value="'+t.replace(/"/g,'&quot;')+'">');};
        $('mc').appendChild(delBtn);
    }
    $('exp').onchange=function(){$('custExp').style.display=this.value==='custom'?'block':'none';};
    $('max').onchange=function(){$('custMax').style.display=this.value==='custom'?'block':'none';};
}
function copyLink(id){const el=$(id);el.select();document.execCommand('copy');showToast('<?=T('sh_ok')?>');}
window.onclick=e=>{if(e.target.className==='mod') cl();};
if(quick){copyLink('q_lnk');history.replaceState(null,'',location.pathname+location.search.replace(/[\?&]quick=[^&]+/, '').replace(/^&/, '?'));}
</script></body></html><?php } } ?>
