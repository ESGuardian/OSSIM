<STYLE TYPE="text/css">
<!-- 
BODY { 
font-family:Verdana;
}  
--> 
</STYLE> 
<body><font size="2">
<?php 
    if (@$_POST['plugin_value_type']) {
        $form_plugin_value_type =  @$_POST['plugin_value_type']; 
    } else {
        $form_plugin_value_type =  "";
    }
    if (@$_POST['plugin_operator']) {
        $form_plugin_operator =  @$_POST['plugin_operator']; 
    } else {
        $form_plugin_operator =  "";
    }
    if (@$_POST['plugin_value']) {
        $form_plugin_value =  @$_POST['plugin_value']; 
    } else {
        $form_plugin_value =  "";
    }
    if (@$_POST['signature_value_type']) {
        $form_signature_value_type =  @$_POST['signature_value_type']; 
    } else {
        $form_signature_value_type =  "";
    }
    if (@$_POST['signature_operator']) {
        $form_signature_operator =  @$_POST['signature_operator']; 
    } else {
        $form_signature_operator =  "";
    }
    if (@$_POST['signature_value']) {
        $form_signature_value =  @$_POST['signature_value']; 
    } else {
        $form_signature_value =  "";
    }
    if (@$_POST['username']) {
        $form_username = @$_POST['username'];
    } else {
        $form_username = "";
    }
    if (@$_POST['src_ip']) {
        $form_src_ip = @$_POST['src_ip'];
    } else {
        $form_src_ip = "";
    }
    if (@$_POST['dst_ip']) {
        $form_dst_ip = @$_POST['dst_ip'];
    } else {
        $form_dst_ip = "";
    }
    if (@$_POST['text_operator']) {
        $form_text_operator = @$_POST['text_operator'];
    } else {
        $form_text_operator = "text";
    }
    if (@$_POST['text_value']) {
        $form_text_value = @$_POST['text_value'];
    } else {
        $form_text_value = "";
    }
    if (@$_POST['date']) {
        $form_date = @$_POST['date'];
    } else {
        $form_date = date('Y-m-d');
    }
    if (@$_POST['time_operator']) {
        $form_time_operator =  @$_POST['time_operator'];
    } else{
        $form_time_operator = "gte";
    }
    if (@$_POST['time']) {
        $form_time = @$_POST['time'];
    } else {
        $form_time = '00:00:00';
    }
    if (@$_GET['command']) {
        $command = @$_GET['command'];
    } else {
        $command = "";
    }
    if (@$_GET['id']) {
        $form_id = @$_GET['id'];
    }else {
        $form_id = "";
    }

?> 

<table border="0" bgcolor="#E6E6E6" width="100%">
<form action="reader.php?command=find" name="request" method="post">
<tr>
<td style="width:150px;font-size:12">Плагин:</td> 
<td style="width:800px;font-size:12">
<select class="input" type="text" style="width:150px; font-size:12" name="plugin_value_type">
<?php 
$values = array("plugin_name", "plugin_id");
foreach ($values as $value) {
    if ($value == $form_plugin_value_type) {
        echo '<option value="'. $value . '" selected>'. $value.'</option>';
    } else {
        echo '<option value="'. $value . '">'. $value .'</option>';
    } 
}
?>
</select>
<input type="text" style="width:150px; font-size:12"  name="plugin_operator"  value="равно" readonly>
<?php
echo '<input type="text" style="width:300px; font-size:12"  name="plugin_value"  value="' . $form_plugin_value . '">'
?>
</td></tr>
<tr>
<td style="width:150px;font-size:12">Сигнатура:</td> 
<td style="width:800px;font-size:12">
<select class="input" type="text" style="width:150px; font-size:12" name="signature_value_type">
<?php 
$values = array("signature_name", "signature_id");
foreach ($values as $value) {
    if ($value == $form_signature_value_type) {
        echo '<option value="'. $value . '" selected>'. $value.'</option>';
    } else {
        echo '<option value="'. $value . '">'. $value .'</option>';
    } 
}
?>
</select>
<input type="text" style="width:150px; font-size:12" name="signature_operator" value="равно" readonly>
<?php
echo '<input type="text" style="width:300px; font-size:12" name="signature_value" value="' . $form_signature_value . '">'
?>
</td></tr>
<tr>
<td style="width:150px;font-size:12">username:</td>
<td style="width:800px;font-size:12">
<?php
echo '<input type="text" style="width:150px; font-size:12" name="username" value="' . $form_username . '">'
?>
 src_ip:
<?php
echo '<input type="text" style="width:150px; font-size:12" name="src_ip" value="' . $form_src_ip . '">'
?>
 dst_ip:
<?php
echo '<input type="text" style="width:150px; font-size:12" name="dst_ip" value="' . $form_dst_ip . '">'
?>
</td></tr>
<tr>
<td style="width:150px;font-size:12">Log (payload):</td>
<td style="width:800px;font-size:12">
<select class="input" style="width:150px; font-size:12" type="text" name="text_operator">
<?php
$text_operators = array("regex"=>"regex", "text"=>"text");
foreach ($text_operators as $key => $value) {
    if ($key == $form_text_operator) {
        echo '<option value="' . $key . '" selected>' . $value . '</option>';
    } else {
        echo '<option value="' . $key . '">' . $value . '</option>';
    }    
}
?>
</select>
<?php
echo '<input type="text" style="width:600px; font-size:12" name="text_value" value="' . $form_text_value . '">';
?>
</td></tr>
<tr>
<td style="width:150px;font-size:12"><input name="submit" type="submit" value="Искать"></td>
<?php
echo '<td style="width:800px;font-size:12"><input type="text" style="width:150px; font-size:12" name="date" value="' . $form_date . '"> ';
echo '<select class="input" type="text" style="width:150px; font-size:12" name="time_operator">';
$time_operators = array("gte"=>"после (UTC)", "lte"=>"до (UTC)");
foreach ($time_operators as $key => $value) {
    if ($key == $form_time_operator) {
        echo '<option value="' . $key . '" selected>' . $value . '</option>';
    } else {
        echo '<option value="' . $key . '">' . $value . '</option>';
    }    
}
echo '</select> ';
echo '<input type="text" style="width:150px; font-size:12" name="time" value="' . $form_time . '">';
?> 
</td></tr>

</form></table>
<hr>
<?php

try {
    // open connection to MongoDB server
    $conn = new Mongo('mongodb://172.16.0.17', array(
        'username' => 'reader',
        'password' => 'pssword',
        'db'       => 'ossim'
    ));



    // access collection
    $subcollection = str_replace("-","", $form_date);
    $collection = $conn->ossim->selectCollection("logger.$subcollection");
    $find_array = array();
    if ($form_time_operator == 'gte'){
        $time_filter = array ('fdate'=> array('$gte' => $form_date . ' ' . $form_time));
    } else {
        $time_filter = array ('fdate'=> array('$lte' => $form_date . ' ' . $form_time));
    }
    $find_array[] = $time_filter;
    if ($form_text_value !="") {
        if ($form_text_operator == 'text') {
            $textIndexPresent = False;
            foreach ($collection->getIndexInfo() as $index){
                if ((in_array('signature_text_log_text',$index)) or (in_array('log_text',$index))){
                    $textIndexPresent = True;
                }            
            }
            if ($textIndexPresent) {
                $find_text = array('$text' => array('$search' => $form_text_value));
            }else{            
                echo '<font size="2">В этой коллекции нет текстового индекса. Поиск будет выполнен с оператором условию "regex"</font><br/>';
                $find_text = array('log' => array('$regex' => new MongoRegex("/.*$form_value.*/i")));
            }        
        }
        $find_array[] = $find_text;
    }
    if ($form_plugin_value != "") {
        if ($form_plugin_value_type == 'plugin_name') {
            $find_plugin = array ('plugin' => $form_plugin_value);
        }else{
            $find_plugin = array ('plugin_id' => (int)$form_plugin_value);
        }
        $find_array[] = $find_plugin;
    }
    if ($form_signature_value !="") {
        if ($form_signature_value_type == 'signature_name') {
            $find_signature = array ('signature' => $form_signature_value);
        }else{
            $find_signature = array ('plugin_sid' => (int)$form_signature_value);
        }
        $find_array[] = $find_signature;
    }
    if ($form_username != ""){
        $find_array[] = array('username' => $form_username);
    }
    if ($form_src_ip != ""){
        $find_array[] = array('src_ip' => $form_src_ip);
    }
    if ($form_dst_ip != "") {
        $find_array[] = array ('dst_ip' => $form_dst_ip);
    }
    
    if ($command == 'find') {
        $cursor = $collection->find(array('$and'=> $find_array))->limit(1000)->timeout(-1)->sort(array('fdate' => -1));
        echo '<font size="2">Найдено записей: ' . number_format($cursor->count()) . ' </font><br/>'; 
//        foreach($_POST as $key=>$value){
//            echo $key . " : " . $value . "<br/>";
//        }
        echo '<hr>';
        foreach ($cursor as $obj) {
            echo '<font size="1"><a href="reader.php?command=view&id=' . $obj['_id'] . '" target="_blank">_id: ' . $obj['_id'] . '</a></font><br/>';
            echo '<font size="1">UTC: ' . @$obj['fdate'] . '</font><br/>';
            echo '<font size="1">Плагин: ' . $obj['plugin_id'] . ' : ' . $obj['plugin'] . '</font><br/>';
            echo '<font size="1">Сигнатура: ' . $obj['plugin_sid'] . ' : '  . $obj['signature'] . '</font><br/>';
            echo '<font size="1">src_ip: ' . @$obj['src_ip'] . ' dst_ip: ' . @$obj['dst_ip'] . ' username: ' . @$obj['username'] .'</font><br/>';
            echo '<font size="1">' . $obj['log'] . '</font><br/>';
            echo '<br/>';
        }
    } elseif ($command == 'view') {
        $cursor = $collection->find(array('_id' => new MongoId($form_id)))->timeout(-1);
        echo '<font size="2">Найдено записей: ' . number_format($cursor->count()) . '</font><br/>'; 
        echo '<hr>';
        foreach ($cursor as $obj) {
            foreach ($obj as $key=>$value) {
                echo '<font size="1">' . $key . ' : ' . $value . '</font><br/>';
            }
            echo '<br/>';
        }
    } else {
        $cursor = $collection->find()->timeout(-1);
        echo '<font size="2">Записей в журнале: ' . number_format($cursor->count()) . ' <br/>'; 
        echo 'Готов к работе </font><br/>';
    }
    
 
 // disconnect from server
    $conn->close();
    } catch (MongoConnectionException $e) {
        echo 'Error connecting to MongoDB server <br/>';
        die('Error connecting to MongoDB server');
    } catch (MongoException $e) {
        echo 'Error: ' . $e->getMessage();
        die('Error: ' . $e->getMessage());
    }
?>
<hr>
<font size="1"><b>ESGUARDIAN Logger для OSSIM. v.0.0.2</b> <br/>Это очень простой но очень эффективный логгер всех событий OSSIM. Открытый код, свободное использование.(c) esguardian@outlook.com.</font>
<hr>
</font></body>
