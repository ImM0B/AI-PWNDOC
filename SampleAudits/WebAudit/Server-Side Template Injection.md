While reviewing the application, I realized that the “message” parameter, which the user received as an alert, could be manipulated by the user and was vulnerable to SSTI.

I tested a sample payload:

```
<=%7*7%>
```

![[SSTI1.png]]

I was able to read /etc/passwd using an SSTI payload:

```
<%=File.open('/etc/passwd').read%>
```

![[SSTI2.png]]