<?php
/**
 * Ultimate WebDAV & File Manager (Pro)
 * Ver: 3.0 | PHP 5.6 - 8.4 Compatible
 * Features: Hidden System Files, Stream I/O, Auto-Config, Modern UI
 */

// ============================================================================
// 1. 系统初始化 (System Init)
// ============================================================================

ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('memory_limit', '512M'); // 逻辑内存
set_time_limit(0); // 允许长连接
ignore_user_abort(true);
date_default_timezone_set('UTC');

// 核心常量定义
define('ROOT_DIR', __DIR__);
define('SCRIPT_NAME', basename($_SERVER['SCRIPT_NAME']));
define('STORAGE_NAME', 'storage');
define('STORAGE_PATH', ROOT_DIR . DIRECTORY_SEPARATOR . STORAGE_NAME);
define('AUTH_FILE', ROOT_DIR . DIRECTORY_SEPARATOR . '.htpasswd');

// 系统文件黑名单 (在列表中隐藏)
define('HIDDEN_FILES', serialize(['.', '..', '.htaccess', '.htpasswd', basename(__FILE__)]));

// ============================================================================
// 2. 环境自检与修复 (Auto-Correction)
// ============================================================================

// [A] 存储目录初始化
if (!file_exists(STORAGE_PATH)) {
    if (!mkdir(STORAGE_PATH, 0755, true)) {
        http_response_code(500); die("Critical Error: Cannot create storage directory.");
    }
}

// [B] 存储目录安全锁 (禁止 HTTP 直接访问)
$storeHt = STORAGE_PATH . DIRECTORY_SEPARATOR . '.htaccess';
if (!file_exists($storeHt)) {
    @file_put_contents($storeHt, "Deny from all");
}

// [C] 根目录路由自动配置
$rootHt = ROOT_DIR . DIRECTORY_SEPARATOR . '.htaccess';
$rules = "DirectoryIndex " . SCRIPT_NAME . "\n" .
         "<IfModule mod_rewrite.c>\nRewriteEngine On\n" .
         "RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]\n" .
         "RewriteCond %{REQUEST_FILENAME} !-f\n" .
         "RewriteCond %{REQUEST_FILENAME} !-d\n" .
         "RewriteRule ^(.*)$ " . SCRIPT_NAME . " [QSA,L]\n</IfModule>\n" .
         "Options -Indexes";

// 仅在校验失败时写入，减少磁盘IO
if (!file_exists($rootHt) || md5(file_get_contents($rootHt)) !== md5($rules)) {
    @file_put_contents($rootHt, $rules);
}

// ============================================================================
// 3. 身份验证流程 (Authentication)
// ============================================================================

// [场景1] 首次初始化：设置密码
if (!file_exists(AUTH_FILE)) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['init_u'], $_POST['init_p'])) {
        $u = trim($_POST['init_u']);
        $p = $_POST['init_p'];
        if (strlen($u) < 1 || strlen($p) < 1) die("Username/Password cannot be empty.");
        
        $hash = password_hash($p, PASSWORD_DEFAULT);
        $conf = "<?php return " . var_export(['u' => $u, 'h' => $hash], true) . ";";
        
        if (file_put_contents(AUTH_FILE, $conf)) {
            header("Location: " . $_SERVER['REQUEST_URI']); exit;
        } else {
            die("Error: Cannot write config file. Check permissions.");
        }
    }
    // 输出初始化界面
    echo_html_setup();
    exit;
}

// [场景2] 登录鉴权
$auth = include AUTH_FILE;
$u = isset($_SERVER['PHP_AUTH_USER']) ? $_SERVER['PHP_AUTH_USER'] : '';
$p = isset($_SERVER['PHP_AUTH_PW']) ? $_SERVER['PHP_AUTH_PW'] : '';

if ($u !== $auth['u'] || !password_verify($p, $auth['h'])) {
    header('WWW-Authenticate: Basic realm="Secure Storage"');
    http_response_code(401);
    die('Unauthorized Access');
}

// ============================================================================
// 4. 请求分发 (Request Dispatch)
// ============================================================================

$server = new DavHandler();

// 处理浏览器表单上传 (非 WebDAV 协议补充)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file_upload'])) {
    $server->handleBrowserUpload();
    exit;
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['new_folder'])) {
    $server->handleBrowserMkdir();
    exit;
}

// 处理 WebDAV 核心请求
$server->serve();

// ============================================================================
// 5. 核心逻辑类 (Core Logic)
// ============================================================================

class DavHandler {
    private $baseUri;
    private $reqPath;
    private $fsPath;
    private $hidden;

    public function __construct() {
        $this->hidden = unserialize(HIDDEN_FILES);
        $this->parsePath();
    }

    // 智能路径解析
    private function parsePath() {
        $uri = rawurldecode(explode('?', $_SERVER['REQUEST_URI'])[0]);
        $scriptDir = dirname($_SERVER['SCRIPT_NAME']);
        $scriptDir = ($scriptDir === '/' || $scriptDir === '\\') ? '' : str_replace('\\', '/', $scriptDir);
        
        $scriptBase = '/' . SCRIPT_NAME;
        
        // 计算 Base URI (用于 WebDAV XML 响应)
        $this->baseUri = $scriptDir . (strpos($uri, $scriptBase) === 0 ? $scriptBase : '');
        
        // 计算相对路径
        $rel = '/';
        if (strpos($uri, $scriptDir) === 0) $rel = substr($uri, strlen($scriptDir));
        if (strpos($rel, $scriptBase) === 0) $rel = substr($rel, strlen($scriptBase));
        
        $this->reqPath = empty($rel) ? '/' : $rel;
        
        // 安全清洗防止穿越
        $safe = str_replace(['../', '..\\'], '', $this->reqPath);
        $this->fsPath = STORAGE_PATH . $safe;
    }

    public function serve() {
        try {
            $m = $_SERVER['REQUEST_METHOD'];
            switch ($m) {
                case 'GET':      $this->doGet(); break;
                case 'PUT':      $this->doPut(); break;
                case 'PROPFIND': $this->doPropfind(); break;
                case 'OPTIONS':  $this->doOptions(); break;
                case 'DELETE':   $this->doDelete(); break;
                case 'MKCOL':    $this->doMkcol(); break;
                case 'COPY':     $this->doCopyMove(false); break;
                case 'MOVE':     $this->doCopyMove(true); break;
                case 'HEAD':     $this->doHead(); break;
                case 'LOCK':     $this->doLock(); break;
                case 'UNLOCK':   $this->doUnlock(); break;
                default:         http_response_code(405); break;
            }
        } catch (Exception $e) { http_response_code(500); }
    }

    // ------------------------------------------------------------------------
    // WebDAV Methods
    // ------------------------------------------------------------------------

    private function doOptions() {
        header('DAV: 1, 2');
        header('Allow: OPTIONS, GET, HEAD, DELETE, PROPFIND, PUT, MKCOL, COPY, MOVE, LOCK, UNLOCK');
        header('MS-Author-Via: DAV');
        exit;
    }

    private function doGet() {
        if (!file_exists($this->fsPath)) { http_response_code(404); exit; }

        // 目录：显示 HTML 界面
        if (is_dir($this->fsPath)) {
            $this->sendHtml();
            exit;
        }

        // 隐形保护：如果用户试图直接请求 .htaccess 等文件
        if ($this->isHidden(basename($this->fsPath))) {
            http_response_code(404); exit;
        }

        // 文件：流式下载
        $size = filesize($this->fsPath);
        header('Content-Type: ' . $this->mime($this->fsPath));
        header('Content-Length: ' . $size);
        header('Last-Modified: ' . gmdate('D, d M Y H:i:s T', filemtime($this->fsPath)));
        header('ETag: "' . md5($this->fsPath . $size) . '"');

        if (ob_get_level()) ob_end_clean();
        $fp = fopen($this->fsPath, 'rb');
        fpassthru($fp);
        fclose($fp);
        exit;
    }

    private function doPut() {
        // 禁止上传系统文件
        if ($this->isHidden(basename($this->fsPath))) { http_response_code(403); exit; }

        $dir = dirname($this->fsPath);
        if (!is_dir($dir)) mkdir($dir, 0755, true);

        $in = fopen('php://input', 'rb');
        $out = fopen($this->fsPath, 'wb');
        
        if ($in && $out) {
            stream_copy_to_stream($in, $out);
            fclose($in); fclose($out);
            http_response_code(201);
        } else {
            http_response_code(500);
        }
    }

    private function doPropfind() {
        if (!file_exists($this->fsPath)) { http_response_code(404); exit; }
        
        $depth = isset($_SERVER['HTTP_DEPTH']) ? (int)$_SERVER['HTTP_DEPTH'] : 1;
        
        header('HTTP/1.1 207 Multi-Status');
        header('Content-Type: application/xml; charset="utf-8"');
        
        echo '<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">';
        
        // 收集文件列表
        $files = [];
        if (is_dir($this->fsPath)) {
            $files[] = $this->fsPath; // 包含自身
            if ($depth !== 0) {
                $raw = scandir($this->fsPath);
                foreach ($raw as $node) {
                    // 严格过滤隐藏文件
                    if ($this->isHidden($node)) continue;
                    $files[] = $this->fsPath . (substr($this->fsPath, -1) === '/' ? '' : '/') . $node;
                }
            }
        } else {
            // 单个文件请求，检查是否隐藏
            if (!$this->isHidden(basename($this->fsPath))) {
                $files[] = $this->fsPath;
            }
        }

        foreach ($files as $f) {
            $sub = substr($f, strlen(STORAGE_PATH));
            if ($sub === false) $sub = '';
            
            // Web 路径编码
            $href = $this->baseUri . str_replace('%2F', '/', rawurlencode($sub));
            $stat = stat($f);
            
            echo '<D:response>';
            echo '<D:href>' . $href . '</D:href>';
            echo '<D:propstat><D:prop>';
            echo '<D:displayname>' . htmlspecialchars(basename($f)) . '</D:displayname>';
            echo '<D:getlastmodified>' . gmdate('D, d M Y H:i:s T', $stat['mtime']) . '</D:getlastmodified>';
            echo '<D:creationdate>' . date('Y-m-d\TH:i:s\Z', $stat['ctime']) . '</D:creationdate>';
            
            if (is_dir($f)) {
                echo '<D:resourcetype><D:collection/></D:resourcetype>';
            } else {
                echo '<D:resourcetype/>';
                echo '<D:getcontentlength>' . sprintf('%u', $stat['size']) . '</D:getcontentlength>';
                echo '<D:getcontenttype>' . $this->mime($f) . '</D:getcontenttype>';
            }
            echo '</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>';
            echo '</D:response>';
        }
        echo '</D:multistatus>';
    }

    private function doDelete() {
        if (!file_exists($this->fsPath)) { http_response_code(404); exit; }
        // 保护根目录不被删除
        if ($this->fsPath == STORAGE_PATH) { http_response_code(403); exit; }
        $this->rm($this->fsPath);
        http_response_code(204);
    }

    private function doMkcol() {
        if (file_exists($this->fsPath)) { http_response_code(405); exit; }
        mkdir($this->fsPath, 0755, true) ? http_response_code(201) : http_response_code(409);
    }

    private function doCopyMove($isMove) {
        $dest = isset($_SERVER['HTTP_DESTINATION']) ? $_SERVER['HTTP_DESTINATION'] : '';
        if (!$dest) { http_response_code(400); exit; }
        
        $u = parse_url($dest);
        $dPath = rawurldecode($u['path']);
        
        // 提取目标相对路径
        if ($this->baseUri !== '/' && strpos($dPath, $this->baseUri) === 0) {
            $dPath = substr($dPath, strlen($this->baseUri));
        } elseif ($this->baseUri === '/' && strpos($dPath, '/') === 0) {
            // BaseUri is root
        } else {
             $sn = '/' . SCRIPT_NAME;
             if (strpos($dPath, $sn) === 0) $dPath = substr($dPath, strlen($sn));
        }

        $target = STORAGE_PATH . $dPath;
        
        // 禁止覆盖或移动到系统文件位置
        if ($this->isHidden(basename($target))) { http_response_code(403); exit; }

        $over = isset($_SERVER['HTTP_OVERWRITE']) ? $_SERVER['HTTP_OVERWRITE'] : 'T';
        if (file_exists($target)) {
            if ($over === 'F') { http_response_code(412); exit; }
            $this->rm($target);
        }

        if ($isMove) {
            rename($this->fsPath, $target) ? http_response_code(201) : http_response_code(500);
        } else {
            $this->cp($this->fsPath, $target);
            http_response_code(201);
        }
    }

    private function doLock() {
        $t = 'urn:uuid:' . uniqid();
        header('Content-Type: application/xml; charset="utf-8"');
        header('Lock-Token: <' . $t . '>');
        echo '<?xml version="1.0" encoding="utf-8"?><D:prop xmlns:D="DAV:"><D:lockdiscovery><D:activelock><D:locktype><D:write/></D:locktype><D:lockscope><D:exclusive/></D:lockscope><D:depth>Infinity</D:depth><D:timeout>Second-3600</D:timeout><D:locktoken><D:href>'.$t.'</D:href></D:locktoken></D:activelock></D:lockdiscovery></D:prop>';
        exit;
    }
    private function doUnlock() { http_response_code(204); }
    private function doHead() { file_exists($this->fsPath) ? http_response_code(200) : http_response_code(404); }

    // ------------------------------------------------------------------------
    // Browser Interface & Uploads
    // ------------------------------------------------------------------------

    public function handleBrowserUpload() {
        if (!is_dir($this->fsPath)) die("Invalid directory");
        $file = $_FILES['file_upload'];
        if ($file['error'] === UPLOAD_ERR_OK) {
            $name = basename($file['name']);
            if (!$this->isHidden($name)) {
                move_uploaded_file($file['tmp_name'], $this->fsPath . '/' . $name);
            }
        }
        header("Location: " . $_SERVER['REQUEST_URI']);
    }

    public function handleBrowserMkdir() {
        if (!is_dir($this->fsPath)) die("Invalid directory");
        $name = trim($_POST['new_folder']);
        if ($name && !$this->isHidden($name)) {
            @mkdir($this->fsPath . '/' . $name);
        }
        header("Location: " . $_SERVER['REQUEST_URI']);
    }

    private function sendHtml() {
        header('Content-Type: text/html; charset=utf-8');
        $list = scandir($this->fsPath);
        
        // 排序
        usort($list, function($a, $b) {
            $ad = is_dir($this->fsPath . '/' . $a);
            $bd = is_dir($this->fsPath . '/' . $b);
            if ($ad === $bd) return strcasecmp($a, $b);
            return $ad ? -1 : 1;
        });

        ?>
        <!DOCTYPE html>
        <html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
        <title>Storage: <?php echo htmlspecialchars($this->reqPath); ?></title>
        <style>
            :root { --p: #007bff; --bg: #f8f9fa; }
            body { font-family: -apple-system, sans-serif; margin: 0; background: var(--bg); color: #333; }
            .head { background: #fff; padding: 15px 20px; border-bottom: 1px solid #ddd; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 5px rgba(0,0,0,0.05); }
            .path { font-weight: 600; font-size: 16px; color: #444; }
            .main { max-width: 900px; margin: 20px auto; background: #fff; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); padding: 10px; }
            .tools { padding: 10px; border-bottom: 1px solid #eee; background: #fafafa; display: flex; gap: 10px; flex-wrap: wrap; }
            .item { display: flex; align-items: center; padding: 10px; border-bottom: 1px solid #f1f1f1; transition: 0.2s; }
            .item:hover { background: #fdfdfd; }
            .item:last-child { border-bottom: none; }
            .icon { font-size: 20px; width: 35px; text-align: center; }
            .name { flex: 1; text-decoration: none; color: #333; font-size: 15px; word-break: break-all; }
            .name:hover { color: var(--p); }
            .meta { font-size: 12px; color: #888; margin-left: 10px; min-width: 70px; text-align: right; }
            .btn { background: var(--p); color: #fff; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 13px; }
            input[type=file] { display: none; }
            form { display: inline-block; margin: 0; }
        </style>
        </head><body>
        <div class="head">
            <div class="path">📂 <?php echo htmlspecialchars($this->reqPath); ?></div>
            <a href="<?php echo dirname($this->baseUri); ?>" style="font-size:12px;color:#999;text-decoration:none">Logout via .htpasswd delete</a>
        </div>
        <div class="main">
            <div class="tools">
                <?php if ($this->reqPath !== '/'): ?>
                    <a href=".." class="btn" style="background:#6c757d;text-decoration:none">⬆ Parent</a>
                <?php endif; ?>
                
                <!-- 上传表单 -->
                <form method="post" enctype="multipart/form-data">
                    <label class="btn">
                        Upload File <input type="file" name="file_upload" onchange="this.form.submit()">
                    </label>
                </form>

                <!-- 新建文件夹表单 -->
                <form method="post">
                    <input type="text" name="new_folder" placeholder="Folder Name" style="padding:5px;border:1px solid #ddd;border-radius:4px" required>
                    <button type="submit" class="btn">New Folder</button>
                </form>
            </div>
            
            <div class="list">
                <?php foreach ($list as $f): 
                    if ($this->isHidden($f)) continue;
                    $full = $this->fsPath . '/' . $f;
                    $isDir = is_dir($full);
                    $href = rawurlencode($f);
                    $icon = $isDir ? '📁' : '📄';
                    $size = $isDir ? '-' : $this->fmt(filesize($full));
                    $date = date('Y-m-d H:i', filemtime($full));
                ?>
                <div class="item">
                    <span class="icon"><?php echo $icon; ?></span>
                    <a href="<?php echo $href; ?>" class="name"><?php echo htmlspecialchars($f); ?></a>
                    <span class="meta"><?php echo $date; ?></span>
                    <span class="meta"><?php echo $size; ?></span>
                </div>
                <?php endforeach; ?>
            </div>
        </div>
        </body></html>
        <?php
    }

    // ------------------------------------------------------------------------
    // Utils
    // ------------------------------------------------------------------------

    private function isHidden($name) {
        return in_array($name, $this->hidden);
    }

    private function rm($p) {
        if (is_dir($p)) { foreach(scandir($p) as $i) if (!$this->isHidden($i)) $this->rm($p.'/'.$i); return rmdir($p); }
        return unlink($p);
    }
    
    private function cp($s, $d) {
        if (is_dir($s)) { mkdir($d); foreach(scandir($s) as $i) if (!$this->isHidden($i)) $this->cp($s.'/'.$i, $d.'/'.$i); }
        else copy($s, $d);
    }

    private function mime($f) {
        $x = strtolower(pathinfo($f, PATHINFO_EXTENSION));
        $m = [
            'txt'=>'text/plain','html'=>'text/html','php'=>'text/plain',
            'jpg'=>'image/jpeg','png'=>'image/png','gif'=>'image/gif','svg'=>'image/svg+xml',
            'mp4'=>'video/mp4','mp3'=>'audio/mpeg','pdf'=>'application/pdf',
            'zip'=>'application/zip','rar'=>'application/octet-stream'
        ];
        return isset($m[$x]) ? $m[$x] : 'application/octet-stream';
    }

    private function fmt($b) {
        $u=['B','KB','MB','GB']; $i=0; while($b>=1024&&$i<3){$b/=1024;$i++;} return round($b,2).' '.$u[$i];
    }
}

// 辅助函数：输出初始设置页面
function echo_html_setup() {
    ?>
    <!DOCTYPE html>
    <html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>System Init</title>
    <style>
        body{background:#f4f6f9;display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;margin:0}
        .box{background:#fff;padding:40px;border-radius:10px;box-shadow:0 10px 25px rgba(0,0,0,0.05);width:300px;text-align:center}
        h2{color:#333;margin-top:0}
        input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:5px;box-sizing:border-box}
        button{width:100%;padding:12px;background:#28a745;color:#fff;border:none;border-radius:5px;font-size:16px;cursor:pointer}
        button:hover{background:#218838}
        .note{font-size:12px;color:#666;margin-top:15px;line-height:1.4}
    </style></head><body>
    <div class="box">
        <h2>Initialize</h2>
        <form method="post">
            <input type="text" name="init_u" placeholder="Set Username" required>
            <input type="password" name="init_p" placeholder="Set Password" required>
            <button type="submit">Complete Setup</button>
        </form>
        <div class="note">Password will be encrypted.<br>To reset, delete <b>.htpasswd</b> file.</div>
    </div></body></html>
    <?php
}
