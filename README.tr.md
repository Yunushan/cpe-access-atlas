# CPE Access Atlas

[English](README.md) · [Türkçe](README.tr.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Русский](README.ru.md)

Türkiye'deki ISS'lerin sağladığı modem ve yönlendiriciler için, yalnızca cihaz
sahibinin veya açıkça yetkilendirilmiş yöneticinin kullanacağı, cihaz yazılımı
sürümüne duyarlı erişim araştırması ve güvenli araçlar.

> [!IMPORTANT]
> İlk hedef olan Türk Telekom ZTE H3600P
> `H3600P V9.0 TTN.10_260210` sürümü için kamuya açık ve doğrulanmış bir
> root/süper-yönetici yöntemi henüz yoktur. Eski WAN/TR-069 yöntemi bu sürümde
> yamalanmıştır. Proje, eski yöntemi çalıştırmak yerine tam sürümü tanır ve
> güvenli biçimde durur.

## Projenin amacı

“H3600 root” gibi genel rehberler; ISS özelleştirmesini, donanım revizyonunu,
tam cihaz yazılımını, elde edilen erişim seviyesini ve kurtarma yolunu çoğu
zaman ayırmaz. CPE Access Atlas bunları ayrı ayrı kaydeder.

Proje şunları sağlar:

- ISS/cihaz/donanım/sürüm bazında makine tarafından okunabilir katalog;
- standart yönetici, ayrıcalıklı web yöneticisi, yerel kabuk, UID 0 root ve
  bootloader erişimi için ayrı durum;
- ağ taraması yapmadan tek bir özel IP adresini doğrulama;
- değişiklik yapmayan plan ve isteğe bağlı açık port kontrolü;
- gizli bilgi içermeyen araştırma raporu şablonu;
- desteklenmeyen sürümlerde güvenli şekilde reddetme;
- İngilizce, Türkçe, Almanca, Fransızca ve Rusça belgeler.

Parola listesi, brute force, sızdırılmış ISS kimlik bilgileri, internet taraması,
özel cihaz yazılımı, üçüncü taraf sanal makine imajı veya otomatik downgrade
içermez.

## ISS kapsamı

| ISS | Mevcut kapsam |
|---|---|
| TurkNet | Kataloglandı; cihaz tarifleri bekleniyor |
| Turkcell Superonline | Kataloglandı; cihaz tarifleri bekleniyor |
| Türksat Kablonet | Kataloglandı; cihaz tarifleri bekleniyor |
| Türk Telekom | Kataloglandı; H3600P tam sürüm araştırma kaydı var |
| Netspeed | Kataloglandı; cihaz tarifleri bekleniyor |
| Vodafone Net | Kataloglandı; cihaz tarifleri bekleniyor |
| Millenicom | Kataloglandı; cihaz tarifleri bekleniyor |

Bir ISS'nin listede bulunması tüm modemlerinin desteklendiği anlamına gelmez.

## İlk hedefin durumu

| Alan | Değer |
|---|---|
| ISS | Türk Telekom |
| Cihaz | ZTE ZXHN H3600P V9 |
| Donanım revizyonu | `V9.0` (doğrulama çözümlenmedi) |
| Cihaz yazılımı | `H3600P V9.0 TTN.10_260210` |
| Standart yerel web yöneticisi | ISS tarafından destekleniyor |
| Ayrıcalıklı web yöneticisi | Engelli; araştırma gerekli |
| Linux root kabuğu | Desteklenmiyor |
| Son kanıt incelemesi | 11 Ağustos 2026 |

Ayrıntılar için [uyumluluk tablosuna](SUPPORT.md) ve
[tam sürüm araştırma notuna](docs/research/zte-h3600p-ttn10-260210.md) bakın.

## Hızlı başlangıç

Python 3.11 veya daha yeni bir sürüm gerekir. Kurulum, katalog şemasını çalışma
zamanında doğrulamak için JSON Schema doğrulayıcısını da yükler.

```shell
python -m pip install -e .
cpe-atlas providers
cpe-atlas recipes
cpe-atlas validate
```

Tam hedefi sorgulayın:

```shell
cpe-atlas status \
  --isp "Türk Telekom" \
  --model "ZTE H3600P" \
  --hardware-revision "V9.0" \
  --firmware "H3600P V9.0 TTN.10_260210"
```

Değişiklik yapmayan planı görüntüleyin:

```shell
cpe-atlas plan \
  --isp "turk-telekom" \
  --model "H3600P" \
  --hardware-revision "V9.0" \
  --firmware "H3600P V9.0 TTN.10_260210"
```

Ağ bağlantısı kurmadan tek yerel hedefi doğrulayın:

```shell
cpe-atlas doctor --host 192.168.1.1
```

Yalnızca açıkça belirtilen portları kontrol etmek için `--probe` eklenebilir.
`apply` komutu 0.2.0 sürümünde kasıtlı olarak kapalıdır; sahiplik onayı verilse
bile bu engelli tarifte hiçbir değişiklik yapmaz.

## Erişim terimleri

- **Standart web yöneticisi:** ISS'nin sunduğu yerel ayar hesabı.
- **Ayrıcalıklı web yöneticisi:** bazen `root` veya `sUser` adlı gizli/yüksek
  yetkili web hesabı.
- **Yerel kabuk:** SSH, Telnet, seri bağlantı veya benzeri komut satırı.
- **Root kabuğu:** işletim sisteminde UID 0 yetkili kabuk.
- **Bootloader:** işletim sistemi başlamadan önceki U-Boot benzeri erişim.

Web arayüzünde “root” adlı bir hesap Linux root kabuğu anlamına gelmez.

## Güvenlik ve yetki

- Yalnızca size ait veya yönetmek için açık izin aldığınız cihazları kullanın.
- Modeli, donanım revizyonunu, ISS sürümünü ve cihaz yazılımını tam doğrulayın.
- İnternet, VoIP, IPTV, VLAN, Wi-Fi ve kimlik doğrulama ayarlarını kaydedin.
- Değişiklikten önce test edilmiş bir kurtarma yolu oluşturun.
- `config.bin`, paket yakalama, parola, sertifika, seri numarası, MAC adresi ve
  abone bilgisini depoya yüklemeyin.
- Kiralık, ödünç veya ISS'ye ait cihazlarda sağlayıcının açık izni gerekir.

Değişiklikler bağlantıyı, VoIP/IPTV'yi, güncellemeleri, uzaktan desteği,
garantiyi veya sözleşme koşullarını etkileyebilir.

## Katkı ve lisans

Yeni cihaz tarifi göndermeden önce [CONTRIBUTING.md](CONTRIBUTING.md) ve
[SECURITY.md](SECURITY.md) dosyalarını okuyun. Bir yöntem ancak tam cihaz ve
sürüm üzerinde kurtarma yolu da test edildikten sonra **Doğrulandı** sayılır.

Proje herhangi bir ISS veya üreticiyle bağlantılı değildir. Kod ve özgün
belgeler, garanti verilmeksizin [BSD Zero Clause](LICENSE) (`0BSD`) lisansıyla
sunulur. Lisans, size ait olmayan cihazlara erişim izni vermez.
