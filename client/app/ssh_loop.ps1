$gateway=$args[0]
Set-Content "C:\docker\sdp\client\app\e" 0
while([IO.File]::ReadAllText("C:\docker\sdp\client\app\e").trim() -eq 0){
	$session_id = [IO.File]::ReadAllText("C:\docker\sdp\client\app\session_id").trim()
	if($session_id -ne "") {
		echo "Session ID received, establish TLS tunnel - "$session_id
		ssh -D 50000 -N -C -q $session_id@$gateway -p50022
		echo "TLS tunnel disconnected, clear session id"
		Clear-Content C:\docker\sdp\client\app\session_id
	}
	Start-Sleep -s 1
}