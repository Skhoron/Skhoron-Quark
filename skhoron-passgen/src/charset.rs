//! Наборы символов для генерации паролей и расчёт энтропии.
//!
//! Это не криптографический примитив — просто данные и арифметика,
//! поэтому пишем сами, без внешних библиотек.

#[derive(Debug, Clone, Copy)]
pub struct CharsetOptions {
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
    /// Исключить визуально похожие символы (0/O, 1/l/I, а также `|`,
    /// который легко спутать с `l`/`I` в некоторых шрифтах) — удобство
    /// ручного ввода/переписывания за счёт небольшого снижения алфавита.
    pub exclude_ambiguous: bool,
}

impl Default for CharsetOptions {
    fn default() -> Self {
        Self {
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
        }
    }
}

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{}<>?/.,;:~";
/// Исключаемые при `exclude_ambiguous`: 0/O, 1/l/I, и `|` (визуально
/// близок к l/I в некоторых моноширинных шрифтах) — комментарий и
/// содержимое теперь согласованы (ранее `|` исключался, но не был
/// упомянут в комментарии).
const AMBIGUOUS: &str = "0O1lI|";

/// Собирает алфавит из выбранных опций. Возвращает Vec<char> без дублей,
/// в детерминированном порядке (важно для воспроизводимости построения,
/// не для безопасности — сам выбор символов из алфавита будет случайным).
pub fn build_charset(opts: CharsetOptions) -> Vec<char> {
    let mut alphabet = String::new();
    if opts.lower {
        alphabet.push_str(LOWER);
    }
    if opts.upper {
        alphabet.push_str(UPPER);
    }
    if opts.digits {
        alphabet.push_str(DIGITS);
    }
    if opts.symbols {
        alphabet.push_str(SYMBOLS);
    }

    let mut chars: Vec<char> = alphabet.chars().collect();
    if opts.exclude_ambiguous {
        chars.retain(|c| !AMBIGUOUS.contains(*c));
    }
    chars.sort_unstable();
    chars.dedup();
    chars
}

/// Энтропия пароля в битах: log2(alphabet_size) * length.
///
/// Это ТЕОРЕТИЧЕСКАЯ верхняя граница — размер пространства равновероятных
/// комбинаций при условии, что каждый символ выбирается независимо и
/// равновероятно (именно это обеспечивает rejection sampling в
/// generator.rs). Это не измерение фактической энтропии конкретной
/// сгенерированной строки.
pub fn entropy_bits(alphabet_len: usize, length: usize) -> f64 {
    (alphabet_len as f64).log2() * (length as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_charset_has_no_duplicates_and_reasonable_size() {
        let chars = build_charset(CharsetOptions::default());
        let mut sorted = chars.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(chars.len(), sorted.len(), "charset must not contain duplicates");
        assert!(chars.len() > 80);
    }

    #[test]
    fn exclude_ambiguous_removes_confusing_chars() {
        let opts = CharsetOptions {
            exclude_ambiguous: true,
            ..Default::default()
        };
        let chars = build_charset(opts);
        for c in AMBIGUOUS.chars() {
            assert!(!chars.contains(&c), "ambiguous char {c} should be excluded");
        }
    }

    #[test]
    fn entropy_matches_actual_charset_size() {
        // Раньше тест использовал магическое число 94, которое могло
        // разойтись с реальным размером SYMBOLS/LOWER/UPPER/DIGITS.
        // Теперь считаем от фактически построенного алфавита.
        let chars = build_charset(CharsetOptions::default());
        let expected = (chars.len() as f64).log2() * 20.0;
        let actual = entropy_bits(chars.len(), 20);
        assert!((actual - expected).abs() < 1e-9);
    }

    #[test]
    fn charset_all_options_disabled_is_empty() {
        let opts = CharsetOptions {
            lower: false,
            upper: false,
            digits: false,
            symbols: false,
            exclude_ambiguous: false,
        };
        assert!(build_charset(opts).is_empty());
    }

    #[test]
    fn charset_single_class_only() {
        let opts = CharsetOptions {
            lower: true,
            upper: false,
            digits: false,
            symbols: false,
            exclude_ambiguous: false,
        };
        let chars = build_charset(opts);
        assert_eq!(chars.len(), 26);
    }
}