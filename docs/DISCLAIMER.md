# ⚠️ Disclaimer / Дисклеймер

**English:**

Skhoron-Quark is an experimental, research/educational cryptographic
project. It has **NOT** been independently audited, has **NOT** been
reviewed by the professional cryptography community, and has **NOT**
undergone the years of public cryptanalysis that battle-tested standards
(AES, ChaCha20, etc.) have.

**Do not use Skhoron-Quark to protect real user data, money, or
communications.** For production use, use audited, standardized
primitives: AES-256-GCM or XChaCha20-Poly1305 (e.g. via the RustCrypto
`aes-gcm` / `chacha20poly1305` crates).

This project exists to practice and demonstrate cipher design methodology
(ARX construction, key derivation, AEAD composition) in the open, following
Kerckhoffs's principle — publishing the design from day one rather than
after the fact — so that anyone interested can review, critique, or learn
from it.

---

**Русский:**

Skhoron-Quark — экспериментальный исследовательский/учебный
криптографический проект. Он **НЕ** прошёл независимый аудит, **НЕ** был
проверен профессиональным криптографическим сообществом и **НЕ** прошёл
те годы публичного криптоанализа, которые прошли проверенные временем
стандарты (AES, ChaCha20 и т.д.).

**Не используйте Skhoron-Quark для защиты реальных пользовательских
данных, денег или переписки.** Для продакшена используйте
аудированные, стандартизированные примитивы: AES-256-GCM или
XChaCha20-Poly1305 (например, через крейты `aes-gcm` / `chacha20poly1305`
из экосистемы RustCrypto).

Этот проект существует, чтобы практиковать и демонстрировать методологию
проектирования шифров (ARX-конструкция, вывод ключей, композиция AEAD)
открыто, следуя принципу Керкгоффса — публикуя дизайн с первого дня, а
не после факта — чтобы любой заинтересованный мог его проверить,
покритиковать или на нём поучиться.