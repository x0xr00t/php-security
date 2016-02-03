<?php

function pastebin_login() {
  $api_dev_key = $_ENV['api_dev_key'];
  $api_user_name = $_ENV['api_user_name'];
  $api_user_password = $_ENV['api_user_password'];
  $api_user_name = urlencode($api_user_name);
  $api_user_password = urlencode($api_user_password);
  $url = 'http://pastebin.com/api/api_login.php';
  $ch = curl_init($url);
  curl_setopt($ch, CURLOPT_POST, true);
  curl_setopt($ch, CURLOPT_POSTFIELDS, 'api_dev_key='.$api_dev_key.
  '&api_user_name='.$api_user_name.
  '&api_user_password='.$api_user_password.
  '');
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
  curl_setopt($ch, CURLOPT_VERBOSE, 0);
  curl_setopt($ch, CURLOPT_NOBODY, 0);
  $response = curl_exec($ch);
  return $response;
}

function pastebin_log($user_key, $log) {
  $api_dev_key = $_ENV['api_dev_key']; // your api_developer_key
  $api_paste_code = $log; // your paste text
  $api_paste_private = '1'; // 0=public 1=unlisted 2=private
  $api_paste_name = 'tripwire log ' + date(DATE_RFC2822); // name or title of your paste
  $api_paste_expire_date = '1H';
  $api_paste_format = 'text';
  $api_user_key = $user_key; // if an invalid api_user_key or no key is used, the paste will be create as a guest
  $api_paste_name = urlencode($api_paste_name);
  $api_paste_code = urlencode($api_paste_code);
  $url = 'http://pastebin.com/api/api_post.php';
  $ch = curl_init($url);
  curl_setopt($ch, CURLOPT_POST, true);
  curl_setopt($ch, CURLOPT_POSTFIELDS, 'api_option=paste&api_user_key='.$api_user_key.
  '&api_paste_private='.$api_paste_private.
  '&api_paste_name='.$api_paste_name.
  '&api_paste_expire_date='.$api_paste_expire_date.
  '&api_paste_format='.$api_paste_format.
  '&api_dev_key='.$api_dev_key.
  '&api_paste_code='.$api_paste_code.
  '');
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
  curl_setopt($ch, CURLOPT_VERBOSE, 0);
  curl_setopt($ch, CURLOPT_NOBODY, 0);
  $response = curl_exec($ch);
  return $response;
}

function slackbot_log($text) {
  echo $text;
  $USERNAME = $_ENV['slack_username'];
  $CHANNEL = $_ENV['slack_channel'];
  $ICON = ":ghost:";
  $payload = array(
    "channel" => $CHANNEL,
    "username" => $USERNAME,
    "text" => $text,
    "icon_emoji" => $ICON
  );
  $url = $_ENV['slack_url'];
  //send to slack
  $ch = curl_init();
  curl_setopt($ch, CURLOPT_URL, $url);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
  curl_setopt($ch, CURLOPT_POSTFIELDS, "payload=" . json_encode($payload));
  $result = curl_exec($ch);
  echo $result;
  curl_close($ch);
  return $result;
}
?>
