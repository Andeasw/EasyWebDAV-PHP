<?php
/**
 * EasyWebDAV - Single-File WebDAV Server
 * Features: Secured Path, No Upload Limits, Modern UI
 * By Prince | https://github.com/Andeasw/EasyWebDAV-PHP
 */

// 核心配置
@error_reporting(0);
@set_time_limit(0); 
@ignore_user_abort(true);
date_default_timezone_set('UTC');

define('ROOT_DIR', __DIR__);
define('SCRIPT_NAME', basename($_SERVER['SCRIPT_NAME']));
define('SCRIPT_URI', $_SERVER['SCRIPT_NAME']);
define('STORAGE_NAME', 'storage');
define('STORAGE_PATH', ROOT_DIR . DIRECTORY_SEPARATOR . STORAGE_NAME);
define('AUTH_FILE', ROOT_DIR . DIRECTORY_SEPARATOR . '.htpasswd.php');

define('PROTECTED_FILES', serialize([
    '.', '..', '.htaccess', '.htpasswd', '.htpasswd.php', SCRIPT_NAME, basename(__FILE__)
]));

// 环境初始化
if (!file_exists(STORAGE_PATH)) {
    @mkdir(STORAGE_PATH, 0755, true);
}

$storeHt = STORAGE_PATH . DIRECTORY_SEPARATOR . '.htaccess';
if (!file_exists($storeHt)) {
    $rules = "<IfModule mod_php5.c>\nphp_flag engine off\n</IfModule>\n" .
             "<IfModule mod_php7.c>\nphp_flag engine off\n</IfModule>\n" .
             "<IfModule mod_php.c>\nphp_flag engine off\n</IfModule>\n" .
             "RemoveHandler .php .phtml .php3 .php4 .php5\n" .
             "Deny from all";
    @file_put_contents($storeHt, $rules);
}

$rootHt = ROOT_DIR . DIRECTORY_SEPARATOR . '.htaccess';
if (!file_exists($rootHt)) {
    $rules = "Options -Indexes\n" .
             "<IfModule mod_rewrite.c>\n" .
             "RewriteEngine On\n" .
             "RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]\n" .
             "</IfModule>\n" .
             "AcceptPathInfo On\n";
    @file_put_contents($rootHt, $rules);
}

// 身份验证
if (empty($_SERVER['PHP_AUTH_USER'])) {
    $h = isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION'] : 
         (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION']) ? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] : '');
    if ($h && preg_match('/Basic\s+(.*)$/i', $h, $m)) {
        list($u, $p) = explode(':', base64_decode($m[1]), 2);
        $_SERVER['PHP_AUTH_USER'] = $u;
        $_SERVER['PHP_AUTH_PW']   = $p;
    }
}

if (!file_exists(AUTH_FILE)) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['u']) && !empty($_POST['p'])) {
        $hash = password_hash($_POST['p'], PASSWORD_DEFAULT);
        $data = "<?php return " . var_export(['u' => trim($_POST['u']), 'h' => $hash], true) . ";";
        if (@file_put_contents(AUTH_FILE, $data)) {
            header("Location: " . SCRIPT_URI); exit;
        }
    }
    echo_html_setup();
    exit;
}

$auth = include AUTH_FILE;
if (empty($_SERVER['PHP_AUTH_USER']) || $_SERVER['PHP_AUTH_USER'] !== $auth['u'] || !password_verify($_SERVER['PHP_AUTH_PW'], $auth['h'])) {
    header('WWW-Authenticate: Basic realm="EasyWebDAV"');
    header('HTTP/1.0 401 Unauthorized');
    die('Access Denied');
}

// 请求分发
$server = new DavHandler();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $ref = isset($_SERVER['HTTP_REFERER']) ? parse_url($_SERVER['HTTP_REFERER'], PHP_URL_HOST) : null;
    if ($ref && $ref !== $_SERVER['HTTP_HOST']) die('CSRF Error');

    if (isset($_FILES['file'])) $server->handleBrowserUpload();
    if (isset($_POST['mkdir'])) $server->handleBrowserMkdir();
    
    if (empty($_FILES) && empty($_POST)) $server->serve();
    else exit;
} else {
    $server->serve();
}

class DavHandler {
    private $baseUri;
    private $reqPath;
    private $fsPath;
    private $protect;

    public function __construct() {
        $this->protect = unserialize(PROTECTED_FILES);
        $this->parsePath();
    }

    private function parsePath() {
        $this->baseUri = SCRIPT_URI;
        $uri = rawurldecode(explode('?', $_SERVER['REQUEST_URI'])[0]);
        
        if (strpos($uri, $this->baseUri) === 0) {
            $rel = substr($uri, strlen($this->baseUri));
        } else {
            $rel = '/';
        }
        
        $this->reqPath = empty($rel) ? '/' : $rel;
        
        $parts = [];
        foreach (explode('/', str_replace('\\', '/', $this->reqPath)) as $p) {
            if ($p === '' || $p === '.') continue;
            if ($p === '..') array_pop($parts);
            else $parts[] = $p;
        }
        $this->fsPath = STORAGE_PATH . DIRECTORY_SEPARATOR . implode(DIRECTORY_SEPARATOR, $parts);
    }

    public function serve() {
        try {
            switch ($_SERVER['REQUEST_METHOD']) {
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

    private function doOptions() {
        header('DAV: 1, 2');
        header('Allow: OPTIONS, GET, HEAD, DELETE, PROPFIND, PUT, MKCOL, COPY, MOVE, LOCK, UNLOCK');
        header('MS-Author-Via: DAV');
        exit;
    }

    private function doGet() {
        if (!file_exists($this->fsPath)) { http_response_code(404); exit; }
        if (is_dir($this->fsPath)) { $this->sendHtml(); exit; }
        if ($this->isProtected(basename($this->fsPath))) { http_response_code(404); exit; }

        $size = filesize($this->fsPath);
        header('Content-Type: application/octet-stream');
        header('Content-Length: ' . $size);
        header('ETag: "' . md5($this->fsPath . $size . filemtime($this->fsPath)) . '"');
        
        while (ob_get_level()) ob_end_clean();
        $fp = fopen($this->fsPath, 'rb');
        fpassthru($fp);
        fclose($fp);
        exit;
    }

    private function doPut() {
        if ($this->isProtected(basename($this->fsPath))) { http_response_code(403); exit; }
        
        $dir = dirname($this->fsPath);
        if (!is_dir($dir)) mkdir($dir, 0755, true);
        
        $in = fopen('php://input', 'rb');
        $out = fopen($this->fsPath, 'wb');
        if ($in && $out) {
            stream_copy_to_stream($in, $out);
            http_response_code(201);
        } else {
            http_response_code(500);
        }
        @fclose($in); @fclose($out);
    }

    private function doPropfind() {
        if (!file_exists($this->fsPath)) { http_response_code(404); exit; }
        $depth = isset($_SERVER['HTTP_DEPTH']) ? (int)$_SERVER['HTTP_DEPTH'] : 1;
        
        header('HTTP/1.1 207 Multi-Status');
        header('Content-Type: application/xml; charset="utf-8"');
        echo '<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">';
        
        $files = [];
        if (is_dir($this->fsPath)) {
            $files[] = $this->fsPath;
            if ($depth !== 0) {
                foreach (scandir($this->fsPath) as $node) {
                    if (!$this->isProtected($node)) $files[] = $this->fsPath . DIRECTORY_SEPARATOR . $node;
                }
            }
        } elseif (!$this->isProtected(basename($this->fsPath))) {
            $files[] = $this->fsPath;
        }

        foreach ($files as $f) {
            $rel = substr($f, strlen(STORAGE_PATH));
            $href = $this->baseUri . implode('/', array_map('rawurlencode', explode('/', str_replace('\\', '/', $rel))));
            $stat = stat($f);
            
            echo '<D:response>';
            echo '<D:href>' . $href . '</D:href>';
            echo '<D:propstat><D:prop>';
            echo '<D:displayname>' . htmlspecialchars(basename($f)) . '</D:displayname>';
            echo '<D:getlastmodified>' . gmdate('D, d M Y H:i:s T', $stat['mtime']) . '</D:getlastmodified>';
            if (is_dir($f)) {
                echo '<D:resourcetype><D:collection/></D:resourcetype>';
            } else {
                echo '<D:resourcetype/>';
                echo '<D:getcontentlength>' . sprintf('%u', $stat['size']) . '</D:getcontentlength>';
            }
            echo '</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>';
            echo '</D:response>';
        }
        echo '</D:multistatus>';
    }

    private function doDelete() {
        if (!file_exists($this->fsPath) || $this->fsPath == STORAGE_PATH) { http_response_code(403); exit; }
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
        
        $path = rawurldecode(parse_url($dest, PHP_URL_PATH));
        if (strpos($path, SCRIPT_NAME) === false) { http_response_code(502); exit; }
        
        $relDest = substr($path, strpos($path, SCRIPT_NAME) + strlen(SCRIPT_NAME));
        $parts = [];
        foreach (explode('/', $relDest) as $p) {
            if ($p == '..') array_pop($parts);
            elseif ($p !== '' && $p !== '.') $parts[] = $p;
        }
        $target = STORAGE_PATH . DIRECTORY_SEPARATOR . implode(DIRECTORY_SEPARATOR, $parts);

        if ($this->isProtected(basename($target))) { http_response_code(403); exit; }
        if (file_exists($target)) {
            if ((isset($_SERVER['HTTP_OVERWRITE']) ? $_SERVER['HTTP_OVERWRITE'] : 'T') === 'F') {
                http_response_code(412); exit;
            }
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
    
    public function handleBrowserUpload() {
        if (is_dir($this->fsPath) && $_FILES['file']['error'] == 0) {
            $n = basename($_FILES['file']['name']);
            if (!$this->isProtected($n)) {
                move_uploaded_file($_FILES['file']['tmp_name'], $this->fsPath . DIRECTORY_SEPARATOR . $n);
            }
        }
        header("Location: " . $_SERVER['REQUEST_URI']);
    }

    public function handleBrowserMkdir() {
        $n = str_replace(['/', '\\'], '', trim($_POST['mkdir']));
        if ($n && !$this->isProtected($n)) @mkdir($this->fsPath . DIRECTORY_SEPARATOR . $n);
        header("Location: " . $_SERVER['REQUEST_URI']);
    }

    private function isProtected($n) { return in_array($n, $this->protect); }
    
    private function rm($p) {
        if (is_dir($p)) {
            foreach(scandir($p) as $i) if ($i !== '.' && $i !== '..') $this->rm($p . DIRECTORY_SEPARATOR . $i);
            rmdir($p);
        } else unlink($p);
    }
    
    private function cp($s, $d) {
        if (is_dir($s)) {
            mkdir($d);
            foreach(scandir($s) as $i) if ($i !== '.' && $i !== '..') $this->cp($s . DIRECTORY_SEPARATOR . $i, $d . DIRECTORY_SEPARATOR . $i);
        } else copy($s, $d);
    }
    
    private function fmt($b) {
        $u = ['B','KB','MB','GB']; $i=0; while($b>=1024&&$i<3){$b/=1024;$i++;} return round($b,2).' '.$u[$i];
    }

    private function sendHtml() {
        if (headers_sent()) return;
        header('Content-Type: text/html; charset=utf-8');
        
        $list = scandir($this->fsPath);
        usort($list, function($a, $b) {
            $ad = is_dir($this->fsPath . '/' . $a);
            $bd = is_dir($this->fsPath . '/' . $b);
            return ($ad === $bd) ? strcasecmp($a, $b) : ($ad ? -1 : 1);
        });

        $bc = []; $acc = '';
        foreach(array_filter(explode('/', $this->reqPath)) as $p) {
            $acc .= '/' . $p; $bc[] = ['n'=>$p, 'p'=>$this->baseUri . $acc];
        }

        $iconFile = '<svg viewBox="0 0 24 24" class="svg-icon"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>';
        $iconFolder = '<svg viewBox="0 0 24 24" class="svg-icon" style="fill:#FBC02D"><path d="M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>';
        $iconUp = '<svg viewBox="0 0 24 24" class="svg-icon"><path d="M11 9l1.42 1.42L8.83 14H18V4h2v12H8.83l3.59 3.58L11 21l-6-6 6-6z"/></svg>';
        $iconUpload = '<svg viewBox="0 0 24 24" class="svg-icon" style="fill:white"><path d="M9 16h6v-6h4l-7-7-7 7h4zm-4 2h14v2H5z"/></svg>';
        ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>EasyWebDAV File Manager</title>
    <style>
        :root { 
            --primary: #3b82f6; 
            --primary-hover: #2563eb;
            --bg: #f3f4f6; 
            --card: #ffffff; 
            --text: #1f2937; 
            --text-light: #6b7280; 
            --border: #e5e7eb;
        }
        * { box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; 
            background: var(--bg); 
            margin: 0; 
            color: var(--text); 
            line-height: 1.5;
        }
        .container { 
            max-width: 1000px; 
            margin: 20px auto; 
            background: var(--card); 
            border-radius: 12px; 
            box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1), 0 2px 4px -1px rgba(0,0,0,0.06); 
            overflow: hidden; 
            display: flex; 
            flex-direction: column; 
            min-height: 85vh; 
        }
        header { 
            padding: 16px 24px; 
            border-bottom: 1px solid var(--border); 
            background: #fff;
        }
        .crumbs { font-size: 15px; color: var(--text-light); display: flex; align-items: center; flex-wrap: wrap; }
        .crumbs a { text-decoration: none; color: var(--primary); font-weight: 600; padding: 4px 8px; border-radius: 4px; transition: background 0.2s; } 
        .crumbs a:hover { background: #eff6ff; }
        .crumbs span { color: #d1d5db; margin: 0 4px; }
        
        .toolbar { 
            padding: 16px 24px; 
            background: #f9fafb; 
            border-bottom: 1px solid var(--border); 
            display: flex; 
            flex-wrap: wrap; 
            gap: 12px; 
            align-items: center; 
        }
        .btn { 
            padding: 8px 16px; 
            border: 1px solid var(--border); 
            background: var(--card); 
            border-radius: 6px; 
            cursor: pointer; 
            font-size: 14px; 
            font-weight: 500;
            color: var(--text); 
            text-decoration: none; 
            display: inline-flex; 
            align-items: center; 
            justify-content: center;
            transition: all 0.2s; 
            height: 38px;
            white-space: nowrap;
        }
        .btn:hover { border-color: var(--primary); color: var(--primary); background: #eff6ff; }
        .btn-primary { 
            background: var(--primary); 
            color: #fff; 
            border-color: var(--primary); 
            position: relative;
            overflow: hidden;
        }
        .btn-primary:hover { background: var(--primary-hover); color: #fff; }
        .svg-icon { width: 20px; height: 20px; fill: currentColor; margin-right: 8px; flex-shrink: 0; }
        
        .upload-form { display: inline-flex; margin: 0; }
        .mkdir-form { display: inline-flex; gap: 8px; flex: 1; max-width: 300px; }
        input[type="text"] { 
            padding: 8px 12px; 
            border: 1px solid var(--border); 
            border-radius: 6px; 
            outline: none; 
            font-size: 14px;
            flex: 1;
            min-width: 0;
        }
        input[type="text"]:focus { border-color: var(--primary); box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2); }
        
        .table-responsive { overflow-x: auto; flex: 1; }
        .file-list { width: 100%; border-collapse: collapse; min-width: 600px; }
        .file-list th { 
            text-align: left; 
            padding: 12px 24px; 
            color: var(--text-light); 
            font-weight: 600; 
            font-size: 13px; 
            border-bottom: 1px solid var(--border); 
            text-transform: uppercase;
            letter-spacing: 0.05em;
            background: #fff;
        }
        .file-list td { padding: 14px 24px; border-bottom: 1px solid #f3f4f6; color: var(--text-light); font-size: 14px; }
        .file-list tr:last-child td { border-bottom: none; }
        .file-list tr:hover { background: #f9fafb; }
        
        .name-cell { display: flex; align-items: center; }
        .file-link { 
            text-decoration: none; 
            color: var(--text); 
            font-weight: 500; 
            display: block; 
            white-space: nowrap; 
            overflow: hidden; 
            text-overflow: ellipsis; 
            max-width: 300px;
        }
        .file-link:hover { color: var(--primary); }
        
        .footer { padding: 16px; background: #f9fafb; border-top: 1px solid var(--border); display: flex; justify-content: center; align-items: center; gap: 8px; color: var(--text-light); font-size: 13px; }
        .gh-link svg { width: 18px; height: 18px; fill: var(--text-light); transition: 0.2s; }
        .gh-link:hover svg { fill: #000; }

        @media (max-width: 768px) {
            .container { margin: 0; border-radius: 0; box-shadow: none; height: 100vh; }
            .file-list { min-width: 100%; }
            .hide-mobile { display: none; } 
            .file-link { max-width: 200px; }
            .mkdir-form { max-width: 100%; width: 100%; }
            .toolbar { flex-direction: column; align-items: stretch; }
            .btn { width: 100%; }
            .upload-form { width: 100%; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="crumbs">
                <a href="<?php echo $this->baseUri; ?>/">Home</a>
                <?php foreach($bc as $b): ?>
                    <span>/</span> <a href="<?php echo $b['p']; ?>"><?php echo htmlspecialchars($b['n']); ?></a>
                <?php endforeach; ?>
            </div>
        </header>
        
        <div class="toolbar">
            <?php if($this->reqPath !== '/'): 
                $parentParts = array_filter(explode('/', $this->reqPath));
                array_pop($parentParts);
                $parentLink = $this->baseUri . '/' . implode('/', array_map('rawurlencode', $parentParts));
            ?>
                <a href="<?php echo $parentLink; ?>" class="btn" style="flex: 0 0 auto; width: auto;"><?php echo $iconUp; ?> Back</a>
            <?php endif; ?>
            
            <form method="post" enctype="multipart/form-data" class="upload-form">
                <label class="btn btn-primary" style="width: 100%; cursor: pointer;">
                    <?php echo $iconUpload; ?> Upload File
                    <input type="file" name="file" accept="*" style="display:none" onchange="this.form.submit()">
                </label>
            </form>

            <form method="post" class="mkdir-form">
                <input type="text" name="mkdir" placeholder="New Folder Name" required autocomplete="off">
                <button class="btn" style="width: auto;">Create</button>
            </form>
        </div>

        <div class="table-responsive">
            <table class="file-list">
                <thead>
                    <tr>
                        <th style="width: 60%">Name</th>
                        <th class="hide-mobile" style="width: 20%">Size</th>
                        <th class="hide-mobile" style="width: 20%">Modified</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach($list as $f): 
                        if($this->isProtected($f)) continue;
                        $p = $this->fsPath . '/' . $f;
                        $isDir = is_dir($p);
                        $href = $this->baseUri . rtrim($this->reqPath, '/') . '/' . rawurlencode($f);
                    ?>
                    <tr>
                        <td>
                            <div class="name-cell">
                                <?php echo $isDir ? $iconFolder : $iconFile; ?>
                                <a href="<?php echo $href; ?>" class="file-link" title="<?php echo htmlspecialchars($f); ?>">
                                    <?php echo htmlspecialchars($f); ?>
                                </a>
                            </div>
                        </td>
                        <td class="hide-mobile"><?php echo $isDir ? '-' : $this->fmt(filesize($p)); ?></td>
                        <td class="hide-mobile"><?php echo date('Y-m-d H:i', filemtime($p)); ?></td>
                    </tr>
                    <?php endforeach; ?>
                    <?php if(count($list) <= 2): ?>
                        <tr><td colspan="3" style="text-align:center;color:#999;padding:40px;">Directory is empty</td></tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>

        <div class="footer">
            <span>EasyWebDAV &copy; <?php echo date('Y'); ?></span>
            <a href="https://github.com/Andeasw/EasyWebDAV-PHP" target="_blank" class="gh-link" title="View on GitHub">
                <svg viewBox="0 0 98 96"><path fill-rule="evenodd" clip-rule="evenodd" d="M48.854 0C21.839 0 0 22 0 49.217c0 21.756 13.993 40.172 33.405 46.69 2.427.49 3.316-1.059 3.316-2.362 0-1.141-.08-5.052-.08-9.127-13.59 2.934-16.42-5.867-16.42-5.867-2.184-5.704-5.42-7.17-5.42-7.17-4.448-3.015.324-3.015.324-3.015 4.934.326 7.523 5.052 7.523 5.052 4.367 7.496 11.404 5.378 14.235 4.074.404-3.178 1.699-5.378 3.074-6.6-10.839-1.141-22.243-5.378-22.243-24.283 0-5.378 1.94-9.778 5.014-13.2-.485-1.222-2.184-6.275.486-13.038 0 0 4.125-1.304 13.426 5.052a46.97 46.97 0 0 1 12.214-1.63c4.125 0 8.33.571 12.213 1.63 9.302-6.356 13.427-5.052 13.427-5.052 2.67 6.763.97 11.816.485 13.038 3.155 3.422 5.015 7.822 5.015 13.2 0 18.905-11.404 23.06-22.324 24.283 1.78 1.548 3.316 4.481 3.316 9.126 0 6.6-.08 11.897-.08 13.526 0 1.304.89 2.853 3.316 2.364 19.412-6.52 33.405-24.935 33.405-46.691C97.707 22 75.788 0 48.854 0z"/></svg>
            </a>
        </div>
    </div>
</body>
</html>
        <?php
    }
}

function echo_html_setup() {
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Setup</title>
    <style>
        body { background: #f3f4f6; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; font-family: -apple-system, sans-serif; }
        .box { background: #fff; padding: 40px; border-radius: 12px; box-shadow: 0 10px 15px -3px rgba(0,0,0,0.1); width: 100%; max-width: 320px; text-align: center; }
        h2 { margin-top: 0; color: #1f2937; margin-bottom: 24px; }
        input { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #d1d5db; border-radius: 6px; box-sizing: border-box; outline: none; transition: 0.2s; }
        input:focus { border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2); }
        button { width: 100%; padding: 12px; background: #3b82f6; color: #fff; border: none; border-radius: 6px; font-size: 16px; font-weight: 500; cursor: pointer; transition: 0.2s; margin-top: 10px; }
        button:hover { background: #2563eb; }
        .footer { margin-top: 24px; font-size: 12px; color: #9ca3af; display: flex; justify-content: center; align-items: center; gap: 6px; }
        .gh-link { opacity: 0.6; display: flex; } .gh-link:hover { opacity: 1; }
        .gh-link svg { width: 16px; height: 16px; fill: #4b5563; }
    </style>
</head>
<body>
    <div class="box">
        <h2>EasyWebDAV Setup</h2>
        <form method="post">
            <input type="text" name="u" placeholder="Set Username" required autocomplete="off">
            <input type="password" name="p" placeholder="Set Password" required autocomplete="new-password">
            <button type="submit">Install Server</button>
        </form>
        <div class="footer">
            By Prince 
            <a href="https://github.com/Andeasw/EasyWebDAV-PHP" target="_blank" class="gh-link">
                <svg viewBox="0 0 98 96" xmlns="http://www.w3.org/2000/svg"><path fill-rule="evenodd" clip-rule="evenodd" d="M48.854 0C21.839 0 0 22 0 49.217c0 21.756 13.993 40.172 33.405 46.69 2.427.49 3.316-1.059 3.316-2.362 0-1.141-.08-5.052-.08-9.127-13.59 2.934-16.42-5.867-16.42-5.867-2.184-5.704-5.42-7.17-5.42-7.17-4.448-3.015.324-3.015.324-3.015 4.934.326 7.523 5.052 7.523 5.052 4.367 7.496 11.404 5.378 14.235 4.074.404-3.178 1.699-5.378 3.074-6.6-10.839-1.141-22.243-5.378-22.243-24.283 0-5.378 1.94-9.778 5.014-13.2-.485-1.222-2.184-6.275.486-13.038 0 0 4.125-1.304 13.426 5.052a46.97 46.97 0 0 1 12.214-1.63c4.125 0 8.33.571 12.213 1.63 9.302-6.356 13.427-5.052 13.427-5.052 2.67 6.763.97 11.816.485 13.038 3.155 3.422 5.015 7.822 5.015 13.2 0 18.905-11.404 23.06-22.324 24.283 1.78 1.548 3.316 4.481 3.316 9.126 0 6.6-.08 11.897-.08 13.526 0 1.304.89 2.853 3.316 2.364 19.412-6.52 33.405-24.935 33.405-46.691C97.707 22 75.788 0 48.854 0z"/></svg>
            </a>
        </div>
    </div>
</body>
</html>
    <?php
}
