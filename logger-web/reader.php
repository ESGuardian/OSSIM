<STYLE TYPE="text/css">
<!-- 
BODY { 
font-family:Verdana; 
}  
--> 
</STYLE> 
<body>
<?php 
    if (@$_POST['field']) {
        $form_field =  @$_POST['field']; 
    } else {
        $form_field =  "";
    }
    if (@$_POST['operator']) {
        $form_operator =  @$_POST['operator'];
    } else{
        $form_operator = "";
    }
    if (@$_POST['value']) {
        $form_value = @$_POST['value'];
    } else {
        $form_value = "";
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

<table border="0" bgcolor="#E6E6E6" width="100%"><tr>
<form action="reader.php?command=find" name="request" method="post"> 
<td><select class="input" type="text" name="field">
<?php 
$fields = array("text","log","plugin","signature","src_ip","dst_ip", "username");
foreach ($fields as $field) {
    if ($field == $form_field) {
        echo '<option value="'. $field . '" selected>'. $field .'</option>';
    } else {
        echo '<option value="'. $field . '">'. $field .'</option>';
    } 
}
?>
</select></td>
<td><select class="input" type="text" name="operator">
<?php
$operators = array("contain"=>"содержит", "eq"=>"равно");
foreach ($operators as $key => $value) {
    if ($key == $form_operator) {
        echo '<option value="' . $key . '" selected>' . $value . '</option>';
    } else {
        echo '<option value="' . $key . '">' . $value . '</option>';
    }    
}
?>
</select></td>
<?php
echo '<td><input type="text" name="value" size="120" value="' . $form_value . '"></td>';
echo '<td><input type="text" name="date" size="8" value="' . $form_date . '"></td>';
echo '<td><select class="input" type="text" name="time_operator">';
$time_operators = array("gte"=>"после (UTC)", "lte"=>"до (UTC)");
foreach ($time_operators as $key => $value) {
    if ($key == $form_time_operator) {
        echo '<option value="' . $key . '" selected>' . $value . '</option>';
    } else {
        echo '<option value="' . $key . '">' . $value . '</option>';
    }    
}
echo '</select></td>';
echo '<td><input type="text" name="time" size="8" value="' . $form_time . '"></td>';
?> 
<td><input name="submit" type="submit" value="Искать"></td>
</form>
</tr></table>
<hr>
<?php

try {
    // open connection to MongoDB server
    $conn = new Mongo('mongodb://172.16.0.17', array(
        'username' => 'reader',
        'password' => 'pass',
        'db'       => 'ossim'
    ));



    // access collection
    $subcollection = str_replace("-","", $form_date);
    $collection = $conn->ossim->selectCollection("logger.$subcollection");
    $find = array();
    if ($form_field == 'text') {
        $textIndexPresent = False;
        foreach ($collection->getIndexInfo() as $index){
            if (in_array('signature_text_log_text',$index)){
                $textIndexPresent = True;
            }            
        }
        if ($textIndexPresent) {
            $find = array('$text' => array('$search' => $form_value));
        }else{            
            echo '<fonnt size="2">В этой коллекции нет текстового индекса. Поиск будет выполнен по условию "log содержит ..."</font><br/>';
            $form_field = 'log';
            $find = array($form_field => array('$regex' => new MongoRegex("/.*$form_value.*/i")));
        }        
    }elseif ($form_operator == 'eq') {
        $find[$form_field] = $form_value;
    }elseif ($form_operator == 'contain') {
        $find = array($form_field => array('$regex' => new MongoRegex("/.*$form_value.*/i")));
    }
    if ($form_time_operator == 'gte'){
        $time_filter = array ('fdate'=> array('$gte' => $form_date . ' ' . $form_time));
    } else {
        $time_filter = array ('fdate'=> array('$lte' => $form_date . ' ' . $form_time));
    }
    

    if ($command == 'find') {
        $cursor = $collection->find(array('$and'=> array($time_filter,$find)))->limit(1000)->timeout(-1)->sort(array('fdate' => -1));
        echo '<font size="2">Найдено записей: ' . number_format($cursor->count()) . ' </font><br/>'; 
        echo '<hr>';
        foreach ($cursor as $obj) {
            echo '<font size="1"><a href="reader.php?command=view&id=' . $obj['_id'] . '" target="_blank">_id: ' . $obj['_id'] . '</a></font><br/>';
            echo '<font size="1">UTC: ' . @$obj['fdate'] . '</font><br/>';
            echo '<font size="1">' . $obj['plugin'] . '</font><br/>';
            echo '<font size="1">' . $obj['signature'] . '</font><br/>';
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
<font size="1"><b>ESGUARDIAN Logger для OSSIM. v.0.0.1</b> <br/>Это очень простой но очень эффективный логгер всех событий OSSIM. Открытый код, свободное использование.(c) esguardian@outlook.com.</font>
<hr>
</body>
