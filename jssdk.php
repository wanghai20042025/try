<?php
header("Content-type: text/html; charset=utf-8");

if (!function_exists('getallheaders')) {
  function getallheaders() {
    $headers = '';
    foreach ($_SERVER as $name => $value) {
      if (substr($name, 0, 5) == 'HTTP_') {
        $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
      }
    }
    return $headers;
  }
}

// 放置临时文件的目录。
define('__TMPDIR__', dirname(__FILE__).'/hy_weixin');
class JSSDK {
  private $appId;
  private $appSecret;

  public function __construct($appId, $appSecret) {
    $this->appId = $appId;
    $this->appSecret = $appSecret;
  }

  public function getSignPackage($url="") {
    $jsapiTicket = $this->getJsApiTicket();

    if($url==""){
      // 注意 URL 一定要动态获取，不能 hardcode.
      $uriPrefix = '';
      $headers = getallheaders();
      if (array_key_exists('X-Uri-Prefix', $headers))
        $uriPrefix = $headers['X-Uri-Prefix'];
      $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
      $url = "$protocol$_SERVER[HTTP_HOST]$uriPrefix$_SERVER[REQUEST_URI]";
    }
    $timestamp = time();
    $nonceStr = $this->createNonceStr();

    // 这里参数的顺序要按照 key 值 ASCII 码升序排序
    $string = "jsapi_ticket=$jsapiTicket&noncestr=$nonceStr&timestamp=$timestamp&url=$url";

    $signature = sha1($string);

    $signPackage = array(
      "appId"     => $this->appId,
      "nonceStr"  => $nonceStr,
      "timestamp" => $timestamp,
      "url"       => $url,
      "signature" => $signature,
      "rawString" => $string
    );
    return $signPackage; 
  }

  public function getJsApiTicket() {
    // jsapi_ticket 应该全局存储与更新，以下代码以写入到文件中做示例

    $jt_file = __TMPDIR__ . '/jsapi_ticket.json';
    //$jt_file = 'fmart_weixin/jsapi_ticket.json';
    if (file_exists($jt_file)) {
      $data = json_decode(file_get_contents($jt_file));
      if (isset($data->expire_time) && $data->expire_time >= time())
        return $data->jsapi_ticket;
    }

    // 如果是企业号用以下 URL 获取 ticket
    $accessToken = $this->getAccessToken();
    // $url = "https://qyapi.weixin.qq.com/cgi-bin/get_jsapi_ticket?access_token=$accessToken";
    $url = "https://api.weixin.qq.com/cgi-bin/ticket/getticket?type=jsapi&access_token=$accessToken";
    $res = json_decode($this->httpGet($url));
    $ticket = $res->ticket;
    if ($ticket) {
      $data = array('expire_time' => time() + 7000, 'jsapi_ticket' => $ticket);
      $fp = fopen($jt_file, "w");
      fwrite($fp, json_encode($data));
      fclose($fp);
    }
    return $ticket;
  }

  public function getAccessToken() {
    // access_token 应该全局存储与更新，以下代码以写入到文件中做示例
    $at_file = __TMPDIR__ . '/access_token.json';
    //$at_file = 'fmart_weixin/access_token.json';
    if (file_exists($at_file)) {
      $data = json_decode(file_get_contents($at_file));
      if (isset($data->expire_time) && $data->expire_time >= time())
        return $data->access_token;
    }

    // 如果是企业号用以下URL获取access_token
    // $url = "https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=$this->appId&corpsecret=$this->appSecret";
    $url = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=$this->appId&secret=$this->appSecret";
    $res = json_decode($this->httpGet($url));
    //echo "res:".json_encode($res);
    //var_dump($res);
    $access_token = $res->access_token;
    if ($access_token) {
      $data = array('expire_time' => time() + 7000, 'access_token' => $access_token);
      $fp = fopen($at_file, "w");
      fwrite($fp, json_encode($data));
      fclose($fp);
    }
    return $access_token;
  }
  
  function write_to_log( $logthis ){
        file_put_contents('logfile.log', date("Y-m-d H:i:s"). " " . $logthis. "\r\n", FILE_APPEND | LOCK_EX);
	}

  public function getUserUnionId($openId) {
	  //write_to_log("getUserUnssssssssssss");
    $url = 'https://api.weixin.qq.com/cgi-bin/user/info?access_token=' . $this->getAccessToken() . '&openid=' . $openId . '&lang=zh_CN';
    $res = json_decode($this->httpGet($url),TRUE);
	write_to_log("res:".json_encode($res));
    if (array_key_exists('openid', $res)) {
		//write_to_log($res['openid']);
      return $res['openid'];
    } else {
      return '';
    }
  }

  private function createNonceStr($length = 16) {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    $str = "";
    for ($i = 0; $i < $length; $i++) {
      $str .= substr($chars, mt_rand(0, strlen($chars) - 1), 1);
    }
    return $str;
  }

  private function httpGet($url) {
    $curl = curl_init();
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($curl, CURLOPT_TIMEOUT, 500);
    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($curl, CURLOPT_URL, $url);

    $res = curl_exec($curl);
    curl_close($curl);

    return $res;
  }
}

