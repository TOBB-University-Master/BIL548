# TOBB ETU BIL548

### Gereksinimler
- Java 17
- Maven

### Giriş
Bu proje güvenli bir sohbet uygulaması geliştirmeyi amaçlamaktadır. 
Proje, Java uygulaması olup soket bağlantısı üzerinden çalışacaktır. 
Ayrıca güvenli giriş protokolü, bağlantı protokolü ve güvenli sohbetin implementasyonunu içermektedir.

### Nasıl Çalışır?
Server ve Client olmak üzere 2 projenin iki modülü bulunmaktadır. 

Server belirtilen port üzerinde (12345 gibi) çalıştıktan sonra istekleri beklemektedir. Gelen isteklere cevap dönmektedir.
Birden fazla client aynı anda bağlanabilecek şekilde tasarlanmıştır. 

Client ise sunucunun dinlediği port üzerinden (12345 gibi) bağlanabilir. Client tarafı kullanıcı gibi çalışmaktadır.
Client kullanıcısı sunucuya belirli mesajları gönderebilir ya da bağlantıyı kapatabilir. 


### Kaynaklar 

- [Proposal Report](https://docs.google.com/document/d/1seTsX2RxPqfnPASRC-owUdP4HkKKZ7wn1lkonPke3gM/edit?usp=sharing)
- [Source Code](https://github.com/TOBB-University-Master/BIL548)