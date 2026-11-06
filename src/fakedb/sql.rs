// SPDX-License-Identifier: GPL-3.0-only
//! A deliberately small SQL expression tokenizer and parser.
//!
//! The honeypot never executes SQL, but it does have to *understand* enough of a
//! `WHERE` clause to answer correctly. This module provides exactly that and
//! nothing more: a flat tokenizer plus a precedence-climbing parser producing an
//! [`Expr`] tree.
//!
//! Everything here treats its input as hostile:
//!
//! * the tokenizer is linear in the input length and bails out past
//!   [`MAX_TOKENS`];
//! * the parser carries an explicit [`Budget`] and a [`MAX_DEPTH`] cap, so a
//!   pathological nesting cannot exhaust the stack or spin the CPU;
//! * anything the grammar does not cover yields `None` instead of a guessed
//!   answer, which lets the caller degrade *conservatively* (fewer rows, never
//!   more).

/// Maximum number of tokens accepted for one expression.
pub const MAX_TOKENS: usize = 2_048;

/// Maximum parenthesis/operator nesting the parser will follow.
pub const MAX_DEPTH: u32 = 24;

/// Interpretation limits a single parse may consume.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    remaining: usize,
}

impl Budget {
    /// A budget that allows `remaining` parser steps.
    pub fn new(remaining: usize) -> Self {
        Self { remaining }
    }

    /// Spend one step; `None` once the budget is exhausted.
    pub fn spend(&mut self) -> Option<()> {
        self.remaining = self.remaining.checked_sub(1)?;
        Some(())
    }

    /// Steps left.
    pub fn remaining(&self) -> usize {
        self.remaining
    }
}

/// A SQL scalar value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// The SQL `NULL`.
    Null,
    /// A signed integer.
    Int(i64),
    /// A double precision number.
    Float(f64),
    /// A character string.
    Text(String),
}

impl Value {
    /// The text protocol rendering of a value (`NULL` stays `None`).
    pub fn to_wire(&self) -> Option<String> {
        match self {
            Self::Null => None,
            Self::Int(number) => Some(number.to_string()),
            Self::Float(number) => Some(format_float(*number)),
            Self::Text(text) => Some(text.clone()),
        }
    }

    /// MySQL truthiness: `NULL` is unknown, numbers are true when non-zero.
    pub fn truthy(&self) -> Option<bool> {
        match self {
            Self::Null => None,
            Self::Int(number) => Some(*number != 0),
            Self::Float(number) => Some(*number != 0.0),
            Self::Text(text) => Some(parse_number(text).is_some_and(|number| number != 0.0)),
        }
    }

    /// Numeric interpretation of the value, if any.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Null => None,
            Self::Int(number) => Some(*number as f64),
            Self::Float(number) => Some(*number),
            Self::Text(text) => parse_number(text),
        }
    }
}

/// Render a float the way MySQL's text protocol does: no exponent for the
/// magnitudes a database actually returns, and no trailing `.0` noise.
pub fn format_float(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_string();
    }
    if value.is_infinite() {
        return if value.is_sign_negative() {
            "-inf".to_string()
        } else {
            "inf".to_string()
        };
    }
    if value == value.trunc() && value.abs() < 1e15 {
        return format!("{}", value as i64);
    }
    format!("{value}")
}

/// Parse a numeric prefix the way MySQL coerces a string to a number.
///
/// MySQL reads the longest numeric prefix and yields `0` for a string with no
/// numeric prefix at all, which is why `'abc' = 0` is true in MySQL.
pub fn parse_number(text: &str) -> Option<f64> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    let bytes = trimmed.as_bytes();
    let mut end = 0usize;
    if matches!(bytes.first(), Some(b'+') | Some(b'-')) {
        end = 1;
    }
    let mut seen_digit = false;
    let mut seen_dot = false;
    let mut seen_exponent = false;
    while end < bytes.len() {
        match bytes[end] {
            b'0'..=b'9' => seen_digit = true,
            b'.' if !seen_dot && !seen_exponent => seen_dot = true,
            b'e' | b'E' if seen_digit && !seen_exponent => seen_exponent = true,
            b'+' | b'-' if seen_exponent && matches!(bytes[end - 1], b'e' | b'E') => {}
            _ => break,
        }
        end += 1;
    }
    if !seen_digit {
        // `''` and `'abc'` both coerce to 0 in a numeric context.
        return Some(0.0);
    }
    trimmed[..end].parse::<f64>().ok()
}

/// One lexical token.
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    /// A bare word: identifier or keyword, original case preserved.
    Word(String),
    /// A backtick quoted identifier.
    Quoted(String),
    /// A string literal.
    Str(String),
    /// A numeric literal, pre-parsed.
    Num(Value),
    /// `@name` — a user variable.
    UserVar(String),
    /// `@@name` — a system variable, scope qualifier already stripped.
    SysVar(String),
    /// A single `?` placeholder from a prepared statement.
    Placeholder,
    /// An operator or punctuation character sequence.
    Sym(Sym),
}

impl Token {
    /// The uppercase keyword form of a word token.
    pub fn keyword(&self) -> Option<String> {
        match self {
            Self::Word(word) => Some(word.to_ascii_uppercase()),
            _ => None,
        }
    }
}

/// Operators and punctuation the grammar distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sym {
    /// `(`
    LParen,
    /// `)`
    RParen,
    /// `,`
    Comma,
    /// `.`
    Dot,
    /// `*`
    Star,
    /// `+`
    Plus,
    /// `-`
    Minus,
    /// `/`
    Slash,
    /// `%`
    Percent,
    /// `=`
    Eq,
    /// `<>` or `!=`
    NotEq,
    /// `<`
    Lt,
    /// `<=`
    Le,
    /// `>`
    Gt,
    /// `>=`
    Ge,
    /// `;`
    Semicolon,
}

/// Comparison and arithmetic operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    /// `AND`
    And,
    /// `OR`
    Or,
    /// `=`
    Eq,
    /// `<>` / `!=`
    NotEq,
    /// `<`
    Lt,
    /// `<=`
    Le,
    /// `>`
    Gt,
    /// `>=`
    Ge,
    /// `+`
    Add,
    /// `-`
    Sub,
    /// `*`
    Mul,
    /// `/`
    Div,
    /// `%`
    Mod,
}

impl BinOp {
    /// Whether the operator compares rather than computes.
    pub fn is_comparison(self) -> bool {
        matches!(
            self,
            Self::Eq | Self::NotEq | Self::Lt | Self::Le | Self::Gt | Self::Ge
        )
    }
}

/// A parsed expression.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// A column reference, lowercased and unqualified.
    Column(String),
    /// A literal value.
    Literal(Value),
    /// `@name`
    UserVar(String),
    /// `@@name`
    SysVar(String),
    /// `name(args)`; `star` records `COUNT(*)`.
    Func {
        /// Uppercased function name.
        name: String,
        /// Arguments.
        args: Vec<Expr>,
        /// `DISTINCT` was present.
        distinct: bool,
        /// The argument list was exactly `*`.
        star: bool,
    },
    /// Unary minus.
    Neg(Box<Expr>),
    /// `NOT expr`
    Not(Box<Expr>),
    /// A binary operator.
    Binary(BinOp, Box<Expr>, Box<Expr>),
    /// `expr IS [NOT] NULL` (also `TRUE`/`FALSE`, normalised to `1`/`0`).
    IsNull {
        /// Operand.
        inner: Box<Expr>,
        /// `IS NOT NULL`
        negated: bool,
    },
    /// `expr [NOT] IN (list)`
    InList {
        /// Operand.
        inner: Box<Expr>,
        /// Candidate list.
        list: Vec<Expr>,
        /// `NOT IN`
        negated: bool,
    },
    /// `expr [NOT] LIKE pattern`
    Like {
        /// Operand.
        inner: Box<Expr>,
        /// Pattern.
        pattern: Box<Expr>,
        /// `NOT LIKE`
        negated: bool,
    },
}

impl Expr {
    /// Whether the tree contains an aggregate function call.
    pub fn contains_aggregate(&self) -> bool {
        match self {
            Self::Func { name, args, .. } => {
                is_aggregate(name) || args.iter().any(Self::contains_aggregate)
            }
            Self::Neg(inner) | Self::Not(inner) => inner.contains_aggregate(),
            Self::Binary(_, left, right) => left.contains_aggregate() || right.contains_aggregate(),
            Self::IsNull { inner, .. } => inner.contains_aggregate(),
            Self::InList { inner, list, .. } => {
                inner.contains_aggregate() || list.iter().any(Self::contains_aggregate)
            }
            Self::Like { inner, pattern, .. } => {
                inner.contains_aggregate() || pattern.contains_aggregate()
            }
            Self::Column(_) | Self::Literal(_) | Self::UserVar(_) | Self::SysVar(_) => false,
        }
    }

    /// Whether the tree is a bare `NAME(*)`-style aggregate.
    pub fn is_aggregate_call(&self) -> bool {
        matches!(self, Self::Func { name, .. } if is_aggregate(name))
    }
}

/// Aggregate function names the evaluator can fold.
pub fn is_aggregate(name: &str) -> bool {
    matches!(
        name.to_ascii_uppercase().as_str(),
        "COUNT" | "MIN" | "MAX" | "SUM" | "AVG" | "GROUP_CONCAT"
    )
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

fn is_word_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_' || byte == b'$' || byte >= 0x80
}

fn is_word_byte(byte: u8) -> bool {
    is_word_start(byte) || byte.is_ascii_digit()
}

/// Tokenize `input`, or `None` when it is malformed or larger than [`MAX_TOKENS`].
pub fn tokenize(input: &str) -> Option<Vec<Token>> {
    let bytes = input.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_whitespace() {
            index += 1;
            continue;
        }
        // Comments: `-- `, `#` and `/* ... */` (including `/*! version */`).
        if byte == b'#' || (byte == b'-' && bytes.get(index + 1) == Some(&b'-')) {
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            continue;
        }
        if byte == b'/' && bytes.get(index + 1) == Some(&b'*') {
            let mut cursor = index + 2;
            loop {
                if cursor + 1 >= bytes.len() {
                    // Unterminated comment: run to the end rather than failing,
                    // the statement is nonsense either way.
                    return Some(tokens);
                }
                if bytes[cursor] == b'*' && bytes[cursor + 1] == b'/' {
                    break;
                }
                cursor += 1;
            }
            index = cursor + 2;
            continue;
        }
        if tokens.len() >= MAX_TOKENS {
            return None;
        }
        match byte {
            b'\'' | b'"' => {
                let (text, next) = read_quoted(bytes, index, byte)?;
                tokens.push(Token::Str(text));
                index = next;
            }
            b'`' => {
                let (text, next) = read_quoted(bytes, index, b'`')?;
                tokens.push(Token::Quoted(text));
                index = next;
            }
            b'@' => {
                let mut cursor = index + 1;
                let system = bytes.get(cursor) == Some(&b'@');
                if system {
                    cursor += 1;
                }
                let start = cursor;
                while cursor < bytes.len() && (is_word_byte(bytes[cursor]) || bytes[cursor] == b'.')
                {
                    cursor += 1;
                }
                let raw = &input[start..cursor];
                if raw.is_empty() {
                    return None;
                }
                if system {
                    tokens.push(Token::SysVar(strip_scope(raw).to_string()));
                } else {
                    tokens.push(Token::UserVar(raw.to_string()));
                }
                index = cursor;
            }
            b'?' => {
                tokens.push(Token::Placeholder);
                index += 1;
            }
            b'0'..=b'9' => {
                let start = index;
                let mut cursor = index;
                let mut seen_dot = false;
                let mut seen_exponent = false;
                while cursor < bytes.len() {
                    match bytes[cursor] {
                        b'0'..=b'9' => {}
                        b'.' if !seen_dot && !seen_exponent => seen_dot = true,
                        b'e' | b'E' if !seen_exponent => seen_exponent = true,
                        _ => break,
                    }
                    cursor += 1;
                }
                let text = &input[start..cursor];
                let value = if seen_dot || seen_exponent {
                    text.parse::<f64>()
                        .map(Value::Float)
                        .unwrap_or(Value::Int(0))
                } else {
                    match text.parse::<i64>() {
                        Ok(number) => Value::Int(number),
                        // Larger than i64: keep it as a float so the value still
                        // renders and compares sensibly.
                        Err(_) => text
                            .parse::<f64>()
                            .map(Value::Float)
                            .unwrap_or(Value::Int(0)),
                    }
                };
                tokens.push(Token::Num(value));
                index = cursor;
            }
            _ if is_word_start(byte) => {
                let start = index;
                let mut cursor = index;
                while cursor < bytes.len() && is_word_byte(bytes[cursor]) {
                    cursor += 1;
                }
                tokens.push(Token::Word(input[start..cursor].to_string()));
                index = cursor;
            }
            _ => {
                let (symbol, consumed) = read_symbol(&bytes[index..])?;
                tokens.push(Token::Sym(symbol));
                index += consumed;
            }
        }
    }
    Some(tokens)
}

/// Read a quoted run, honouring backslash escapes and doubled delimiters.
fn read_quoted(bytes: &[u8], start: usize, delimiter: u8) -> Option<(String, usize)> {
    let mut content = Vec::new();
    let mut cursor = start + 1;
    while cursor < bytes.len() {
        let byte = bytes[cursor];
        if byte == b'\\' && delimiter != b'`' {
            let escaped = *bytes.get(cursor + 1)?;
            content.push(match escaped {
                b'n' => b'\n',
                b't' => b'\t',
                b'r' => b'\r',
                b'0' => b'\0',
                b'b' => 0x08,
                b'Z' => 0x1a,
                other => other,
            });
            cursor += 2;
            continue;
        }
        if byte == delimiter {
            if bytes.get(cursor + 1) == Some(&delimiter) {
                content.push(delimiter);
                cursor += 2;
                continue;
            }
            return Some((String::from_utf8_lossy(&content).into_owned(), cursor + 1));
        }
        content.push(byte);
        cursor += 1;
    }
    // Unterminated literal: refuse rather than inventing a value.
    None
}

fn read_symbol(bytes: &[u8]) -> Option<(Sym, usize)> {
    let first = *bytes.first()?;
    let second = bytes.get(1).copied();
    Some(match (first, second) {
        (b'<', Some(b'>')) | (b'!', Some(b'=')) => (Sym::NotEq, 2),
        (b'<', Some(b'=')) => (Sym::Le, 2),
        (b'>', Some(b'=')) => (Sym::Ge, 2),
        (b'<', _) => (Sym::Lt, 1),
        (b'>', _) => (Sym::Gt, 1),
        (b'=', _) => (Sym::Eq, 1),
        (b'(', _) => (Sym::LParen, 1),
        (b')', _) => (Sym::RParen, 1),
        (b',', _) => (Sym::Comma, 1),
        (b'.', _) => (Sym::Dot, 1),
        (b'*', _) => (Sym::Star, 1),
        (b'+', _) => (Sym::Plus, 1),
        (b'-', _) => (Sym::Minus, 1),
        (b'/', _) => (Sym::Slash, 1),
        (b'%', _) => (Sym::Percent, 1),
        (b';', _) => (Sym::Semicolon, 1),
        _ => return None,
    })
}

/// Drop a `global.` / `session.` / `local.` qualifier from a system variable.
pub fn strip_scope(name: &str) -> &str {
    if let Some((head, tail)) = name.split_once('.') {
        let head = head.trim();
        if head.eq_ignore_ascii_case("global")
            || head.eq_ignore_ascii_case("session")
            || head.eq_ignore_ascii_case("local")
        {
            return tail.trim();
        }
    }
    name.trim()
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Parse a complete expression, requiring the whole token slice to be consumed.
pub fn parse_expression(tokens: &[Token], budget: &mut Budget) -> Option<Expr> {
    let mut cursor = 0usize;
    let expression = parse_or(tokens, &mut cursor, budget, 0)?;
    if cursor == tokens.len() {
        Some(expression)
    } else {
        None
    }
}

struct Cursor<'a> {
    tokens: &'a [Token],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn peek(&self) -> Option<&'a Token> {
        self.tokens.get(self.position)
    }

    fn next(&mut self) -> Option<&'a Token> {
        let token = self.tokens.get(self.position)?;
        self.position += 1;
        Some(token)
    }

    fn at_keyword(&self, keyword: &str) -> bool {
        matches!(self.peek(), Some(Token::Word(word)) if word.eq_ignore_ascii_case(keyword))
    }

    fn eat_keyword(&mut self, keyword: &str) -> bool {
        if self.at_keyword(keyword) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn at_sym(&self, symbol: Sym) -> bool {
        matches!(self.peek(), Some(Token::Sym(known)) if *known == symbol)
    }

    fn eat_sym(&mut self, symbol: Sym) -> bool {
        if self.at_sym(symbol) {
            self.position += 1;
            true
        } else {
            false
        }
    }
}

fn parse_or(tokens: &[Token], cursor: &mut usize, budget: &mut Budget, depth: u32) -> Option<Expr> {
    let mut left = parse_and(tokens, cursor, budget, depth)?;
    loop {
        let mut look = Cursor {
            tokens,
            position: *cursor,
        };
        if !look.eat_keyword("OR") && !look.eat_keyword("XOR") {
            return Some(left);
        }
        // `XOR` has no dedicated node; treating it as `OR` would be wrong, so it
        // is refused and the caller degrades conservatively.
        if look
            .tokens
            .get(*cursor)
            .and_then(Token::keyword)
            .is_some_and(|keyword| keyword == "XOR")
        {
            return None;
        }
        budget.spend()?;
        *cursor = look.position;
        let right = parse_and(tokens, cursor, budget, depth)?;
        left = Expr::Binary(BinOp::Or, Box::new(left), Box::new(right));
    }
}

fn parse_and(
    tokens: &[Token],
    cursor: &mut usize,
    budget: &mut Budget,
    depth: u32,
) -> Option<Expr> {
    let mut left = parse_not(tokens, cursor, budget, depth)?;
    while {
        let mut look = Cursor {
            tokens,
            position: *cursor,
        };
        let matched = look.eat_keyword("AND");
        if matched {
            *cursor = look.position;
        }
        matched
    } {
        budget.spend()?;
        let right = parse_not(tokens, cursor, budget, depth)?;
        left = Expr::Binary(BinOp::And, Box::new(left), Box::new(right));
    }
    Some(left)
}

fn parse_not(
    tokens: &[Token],
    cursor: &mut usize,
    budget: &mut Budget,
    depth: u32,
) -> Option<Expr> {
    if depth > MAX_DEPTH {
        return None;
    }
    let mut look = Cursor {
        tokens,
        position: *cursor,
    };
    if look.eat_keyword("NOT") {
        *cursor = look.position;
        budget.spend()?;
        let inner = parse_not(tokens, cursor, budget, depth + 1)?;
        return Some(Expr::Not(Box::new(inner)));
    }
    parse_comparison(tokens, cursor, budget, depth)
}

fn parse_comparison(
    tokens: &[Token],
    cursor: &mut usize,
    budget: &mut Budget,
    depth: u32,
) -> Option<Expr> {
    let left = parse_additive(tokens, cursor, budget, depth)?;
    budget.spend()?;
    let mut look = Cursor {
        tokens,
        position: *cursor,
    };

    // `[NOT] IN (...)`
    let mut negated_modifier = false;
    if look.at_keyword("NOT") {
        let peek = Cursor {
            tokens,
            position: look.position + 1,
        };
        if peek.at_keyword("IN") || peek.at_keyword("LIKE") {
            negated_modifier = true;
            look.position += 1;
        }
    }
    if look.eat_keyword("IN") {
        look.eat_sym(Sym::LParen);
        let mut list = Vec::new();
        loop {
            budget.spend()?;
            let item = parse_or(tokens, &mut look.position, budget, depth + 1)?;
            list.push(item);
            if look.eat_sym(Sym::Comma) {
                continue;
            }
            break;
        }
        if !look.eat_sym(Sym::RParen) || list.is_empty() {
            return None;
        }
        *cursor = look.position;
        return Some(Expr::InList {
            inner: Box::new(left),
            list,
            negated: negated_modifier,
        });
    }
    if look.eat_keyword("LIKE") {
        let pattern = parse_additive(tokens, &mut look.position, budget, depth + 1)?;
        *cursor = look.position;
        return Some(Expr::Like {
            inner: Box::new(left),
            pattern: Box::new(pattern),
            negated: negated_modifier,
        });
    }
    if negated_modifier {
        return None;
    }
    if look.eat_keyword("IS") {
        let negated = look.eat_keyword("NOT");
        if look.eat_keyword("NULL") {
            *cursor = look.position;
            return Some(Expr::IsNull {
                inner: Box::new(left),
                negated,
            });
        }
        if look.eat_keyword("TRUE") {
            *cursor = look.position;
            let comparison = Expr::Binary(
                BinOp::Eq,
                Box::new(left),
                Box::new(Expr::Literal(Value::Int(1))),
            );
            return Some(if negated {
                Expr::Not(Box::new(comparison))
            } else {
                comparison
            });
        }
        if look.eat_keyword("FALSE") {
            *cursor = look.position;
            let comparison = Expr::Binary(
                BinOp::Eq,
                Box::new(left),
                Box::new(Expr::Literal(Value::Int(0))),
            );
            return Some(if negated {
                Expr::Not(Box::new(comparison))
            } else {
                comparison
            });
        }
        return None;
    }

    let operator = match look.peek() {
        Some(Token::Sym(Sym::Eq)) => BinOp::Eq,
        Some(Token::Sym(Sym::NotEq)) => BinOp::NotEq,
        Some(Token::Sym(Sym::Lt)) => BinOp::Lt,
        Some(Token::Sym(Sym::Le)) => BinOp::Le,
        Some(Token::Sym(Sym::Gt)) => BinOp::Gt,
        Some(Token::Sym(Sym::Ge)) => BinOp::Ge,
        _ => return Some(left),
    };
    look.position += 1;
    let right = parse_additive(tokens, &mut look.position, budget, depth + 1)?;
    *cursor = look.position;
    Some(Expr::Binary(operator, Box::new(left), Box::new(right)))
}

fn parse_additive(
    tokens: &[Token],
    cursor: &mut usize,
    budget: &mut Budget,
    depth: u32,
) -> Option<Expr> {
    let mut left = parse_multiplicative(tokens, cursor, budget, depth)?;
    loop {
        let mut look = Cursor {
            tokens,
            position: *cursor,
        };
        let operator = match look.peek() {
            Some(Token::Sym(Sym::Plus)) => BinOp::Add,
            Some(Token::Sym(Sym::Minus)) => BinOp::Sub,
            _ => return Some(left),
        };
        look.position += 1;
        budget.spend()?;
        let right = parse_multiplicative(tokens, &mut look.position, budget, depth + 1)?;
        *cursor = look.position;
        left = Expr::Binary(operator, Box::new(left), Box::new(right));
    }
}

fn parse_multiplicative(
    tokens: &[Token],
    cursor: &mut usize,
    budget: &mut Budget,
    depth: u32,
) -> Option<Expr> {
    let mut left = parse_unary(tokens, cursor, budget, depth)?;
    loop {
        let mut look = Cursor {
            tokens,
            position: *cursor,
        };
        let operator = match look.peek() {
            Some(Token::Sym(Sym::Star)) => BinOp::Mul,
            Some(Token::Sym(Sym::Slash)) => BinOp::Div,
            Some(Token::Sym(Sym::Percent)) => BinOp::Mod,
            _ => return Some(left),
        };
        look.position += 1;
        budget.spend()?;
        let right = parse_unary(tokens, &mut look.position, budget, depth + 1)?;
        *cursor = look.position;
        left = Expr::Binary(operator, Box::new(left), Box::new(right));
    }
}

fn parse_unary(
    tokens: &[Token],
    cursor: &mut usize,
    budget: &mut Budget,
    depth: u32,
) -> Option<Expr> {
    if depth > MAX_DEPTH {
        return None;
    }
    let mut look = Cursor {
        tokens,
        position: *cursor,
    };
    if look.eat_sym(Sym::Minus) {
        budget.spend()?;
        let inner = parse_unary(tokens, &mut look.position, budget, depth + 1)?;
        *cursor = look.position;
        return Some(Expr::Neg(Box::new(inner)));
    }
    if look.eat_sym(Sym::Plus) {
        let inner = parse_unary(tokens, &mut look.position, budget, depth + 1)?;
        *cursor = look.position;
        return Some(inner);
    }
    parse_primary(tokens, cursor, budget, depth)
}

fn parse_primary(
    tokens: &[Token],
    cursor: &mut usize,
    budget: &mut Budget,
    depth: u32,
) -> Option<Expr> {
    if depth > MAX_DEPTH {
        return None;
    }
    budget.spend()?;
    let mut look = Cursor {
        tokens,
        position: *cursor,
    };
    if look.eat_sym(Sym::LParen) {
        let inner = parse_or(tokens, &mut look.position, budget, depth + 1)?;
        if !look.eat_sym(Sym::RParen) {
            return None;
        }
        *cursor = look.position;
        return Some(inner);
    }
    let token = look.next()?;
    let expression = match token {
        Token::Str(text) => Expr::Literal(Value::Text(text.clone())),
        Token::Num(value) => Expr::Literal(value.clone()),
        Token::Placeholder => Expr::Literal(Value::Null),
        Token::UserVar(name) => Expr::UserVar(name.clone()),
        Token::SysVar(name) => Expr::SysVar(name.clone()),
        Token::Quoted(name) => Expr::Column(name.to_ascii_lowercase()),
        Token::Word(word) => {
            if look.at_sym(Sym::LParen) {
                look.position += 1;
                parse_call(word, tokens, &mut look.position, budget, depth)?
            } else if word.eq_ignore_ascii_case("NULL") {
                Expr::Literal(Value::Null)
            } else if word.eq_ignore_ascii_case("TRUE") {
                Expr::Literal(Value::Int(1))
            } else if word.eq_ignore_ascii_case("FALSE") {
                Expr::Literal(Value::Int(0))
            } else {
                // Consume an optional `schema.`/`table.` qualifier.
                let mut name = word.to_ascii_lowercase();
                while look.at_sym(Sym::Dot) {
                    look.position += 1;
                    match look.next() {
                        Some(Token::Word(part)) => name = part.to_ascii_lowercase(),
                        Some(Token::Quoted(part)) => name = part.to_ascii_lowercase(),
                        _ => return None,
                    }
                }
                Expr::Column(name)
            }
        }
        Token::Sym(_) => return None,
    };
    *cursor = look.position;
    Some(expression)
}

fn parse_call(
    name: &str,
    tokens: &[Token],
    cursor: &mut usize,
    budget: &mut Budget,
    depth: u32,
) -> Option<Expr> {
    let upper = name.to_ascii_uppercase();
    let mut look = Cursor {
        tokens,
        position: *cursor,
    };
    // `COUNT(*)`
    if look.at_sym(Sym::Star) {
        look.position += 1;
        if !look.eat_sym(Sym::RParen) {
            return None;
        }
        *cursor = look.position;
        return Some(Expr::Func {
            name: upper,
            args: Vec::new(),
            distinct: false,
            star: true,
        });
    }
    let mut distinct = false;
    if look.eat_keyword("DISTINCT") {
        distinct = true;
    }
    let mut args = Vec::new();
    if !look.at_sym(Sym::RParen) {
        loop {
            budget.spend()?;
            // `CAST(x AS type)` / `CONVERT(x, type)`: the type name is not an
            // expression, so the argument list is cut at the first `AS`.
            let argument = if matches!(upper.as_str(), "CAST") {
                let end = find_keyword(tokens, look.position, "AS").unwrap_or(tokens.len());
                let mut nested = Budget::new(budget.remaining().max(1));
                let parsed = parse_or(tokens, &mut look.position, &mut nested, depth + 1)?;
                if look.position > end {
                    return None;
                }
                // Everything from `AS` to the closing parenthesis is a type
                // name, not an expression.
                look.position = end;
                while look.position < tokens.len() && !look.at_sym(Sym::RParen) {
                    look.position += 1;
                }
                parsed
            } else {
                parse_or(tokens, &mut look.position, budget, depth + 1)?
            };
            args.push(argument);
            if look.eat_sym(Sym::Comma) {
                continue;
            }
            break;
        }
    }
    if !look.eat_sym(Sym::RParen) {
        return None;
    }
    *cursor = look.position;
    Some(Expr::Func {
        name: upper,
        args,
        distinct,
        star: false,
    })
}

/// Byte-position search for a keyword token at the current nesting level.
fn find_keyword(tokens: &[Token], from: usize, keyword: &str) -> Option<usize> {
    let mut depth = 0i32;
    for (offset, token) in tokens[from..].iter().enumerate() {
        match token {
            Token::Sym(Sym::LParen) => depth += 1,
            Token::Sym(Sym::RParen) => {
                if depth == 0 {
                    return None;
                }
                depth -= 1;
            }
            Token::Word(word) if depth == 0 && word.eq_ignore_ascii_case(keyword) => {
                return Some(from + offset);
            }
            _ => {}
        }
    }
    None
}

/// Split a token slice on top level commas, respecting parentheses.
pub fn split_top_level(tokens: &[Token]) -> Vec<&[Token]> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (index, token) in tokens.iter().enumerate() {
        match token {
            Token::Sym(Sym::LParen) => depth += 1,
            Token::Sym(Sym::RParen) => depth -= 1,
            Token::Sym(Sym::Comma) if depth == 0 => {
                parts.push(&tokens[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&tokens[start..]);
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(sql: &str) -> Option<Expr> {
        let tokens = tokenize(sql)?;
        let mut budget = Budget::new(crate::fakedb::sql::MAX_TOKENS);
        parse_expression(&tokens, &mut budget)
    }

    fn parse_with(sql: &str, steps: usize) -> Option<Expr> {
        let tokens = tokenize(sql)?;
        let mut budget = Budget::new(steps);
        parse_expression(&tokens, &mut budget)
    }

    #[test]
    fn tokenizer_handles_comments_and_quotes() {
        let tokens = tokenize("a /* c */ = 'x''y' -- tail\n").expect("tokens");
        assert_eq!(tokens[0], Token::Word("a".into()));
        assert_eq!(tokens[1], Token::Sym(Sym::Eq));
        assert_eq!(tokens[2], Token::Str("x'y".into()));
        assert_eq!(tokens.len(), 3);

        let tokens = tokenize("'a\\'b'").expect("tokens");
        assert_eq!(tokens[0], Token::Str("a'b".into()));

        let tokens = tokenize("`weird name`").expect("tokens");
        assert_eq!(tokens[0], Token::Quoted("weird name".into()));

        assert!(tokenize("'unterminated").is_none());
        assert!(tokenize("`unterminated").is_none());
    }

    #[test]
    fn tokenizer_recognises_numbers_variables_and_placeholders() {
        let tokens = tokenize("1 2.5 1e3 @a @@global.version ?").expect("tokens");
        assert_eq!(tokens[0], Token::Num(Value::Int(1)));
        assert_eq!(tokens[1], Token::Num(Value::Float(2.5)));
        assert_eq!(tokens[2], Token::Num(Value::Float(1000.0)));
        assert_eq!(tokens[3], Token::UserVar("a".into()));
        assert_eq!(tokens[4], Token::SysVar("version".into()));
        assert_eq!(tokens[5], Token::Placeholder);
    }

    #[test]
    fn parses_comparisons_and_booleans() {
        assert!(parse("id = 1").is_some());
        assert!(parse("id <> 1").is_some());
        assert!(parse("id != 1").is_some());
        assert!(parse("id >= 1 AND id < 5").is_some());
        assert!(parse("a = 1 OR b = 2 AND c = 3").is_some());
        assert!(parse("NOT a = 1").is_some());
        assert!(parse("(a = 1 OR b = 2) AND c = 3").is_some());
    }

    #[test]
    fn or_binds_looser_than_and() {
        // a OR (b AND c)
        let expression = parse("a = 1 OR b = 2 AND c = 3").expect("parse");
        match expression {
            Expr::Binary(BinOp::Or, _, right) => {
                assert!(matches!(*right, Expr::Binary(BinOp::And, _, _)));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parses_in_like_and_is_null() {
        assert!(parse("username IN ('a','b')").is_some());
        assert!(parse("username NOT IN ('a','b')").is_some());
        assert!(parse("username LIKE 'adm%'").is_some());
        assert!(parse("username NOT LIKE 'adm%'").is_some());
        assert!(parse("email IS NULL").is_some());
        assert!(parse("email IS NOT NULL").is_some());
    }

    #[test]
    fn parses_function_calls_and_count_star() {
        match parse("COUNT(*)").expect("parse") {
            Expr::Func { name, star, .. } => {
                assert_eq!(name, "COUNT");
                assert!(star);
            }
            other => panic!("unexpected {other:?}"),
        }
        match parse("COUNT(DISTINCT role)").expect("parse") {
            Expr::Func { name, distinct, .. } => {
                assert_eq!(name, "COUNT");
                assert!(distinct);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(parse("MD5('x')").is_some());
        assert!(parse("CAST('1' AS UNSIGNED)").is_some());
    }

    #[test]
    fn qualified_columns_reduce_to_the_bare_name() {
        match parse("app_prod.users.role = 'admin'").expect("parse") {
            Expr::Binary(_, left, _) => {
                assert_eq!(*left, Expr::Column("role".to_string()));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn unsupported_syntax_is_refused_not_guessed() {
        for sql in [
            "a = (SELECT 1)",
            "CASE WHEN a = 1 THEN 2 END",
            "a BETWEEN 1 AND 2",
            "a XOR b",
            "a = 1 AND",
            "1 =  1 COMPANY",
            "`a`",
        ] {
            // Not all of these must fail, but the ones that do must not panic.
            let _ = parse(sql);
        }
        assert!(parse("a = (SELECT 1)").is_none());
        assert!(parse("a BETWEEN 1 AND 2").is_none());
        assert!(parse("a XOR b").is_none());
        assert!(parse("a = 1 AND").is_none());
    }

    #[test]
    fn deep_nesting_is_rejected_without_recursing_forever() {
        let deep = format!("{}1", "(".repeat(4_000));
        assert!(parse(&deep).is_none(), "unbalanced nesting must fail");

        let balanced = format!("{}1{}", "(".repeat(200), ")".repeat(200));
        assert!(
            parse(&balanced).is_none(),
            "nesting past MAX_DEPTH must be refused"
        );
    }

    #[test]
    fn token_budget_stops_runaway_parsing() {
        let long = (0..400)
            .map(|index| index.to_string())
            .collect::<Vec<_>>()
            .join("+");
        assert!(parse_with(&long, 8).is_none());
    }

    #[test]
    fn tokenizer_refuses_oversized_input() {
        let huge = "a ".repeat(MAX_TOKENS * 2);
        assert!(tokenize(&huge).is_none());
    }

    #[test]
    fn numeric_coercion_matches_mysql() {
        assert_eq!(parse_number("12"), Some(12.0));
        assert_eq!(parse_number(" 12abc"), Some(12.0));
        assert_eq!(parse_number("abc"), Some(0.0));
        assert_eq!(parse_number(""), None);
        assert_eq!(parse_number("-3.5e2"), Some(-350.0));
    }

    #[test]
    fn float_rendering_has_no_exponent_noise() {
        assert_eq!(format_float(12.0), "12");
        assert_eq!(format_float(12.5), "12.5");
        assert_eq!(format_float(-0.5), "-0.5");
    }
}
