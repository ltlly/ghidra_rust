//! SLEIGH `.slaspec` / `.sinc` specification language parser.
//!
//! Parses Ghidra's processor specification language into structured Rust types
//! using `nom` parser combinators.
//!
//! # Grammar overview
//!
//! ```text
//! slaspec ::= definition*
//!
//! definition ::= define_stmt
//!             |  attach_stmt
//!             |  macro_def
//!             |  constructor
//!             |  subconstructor
//!             |  with_block
//!             |  include_directive
//!
//! define_stmt ::= 'define' ( endian | alignment | space | register | token | context | pcodeop ) ';'
//!
//! constructor ::= [table_name ':'] mnemonic operands 'is' pattern [equations] '{' semantics '}'
//! subconstructor ::= table_name ':' mnemonic operands 'is' pattern [equations]
//! with_block ::= 'with' ':' pattern_expr '{' (constructor | subconstructor)* '}'
//! ```
//!
//! # Expressions in semantic sections
//!
//! P-code expressions support arithmetic, logical, comparison, and bitwise
//! operators, as well as function calls, field extraction (`reg[msb,lsb]`),
//! varnode dereference (`*:size offset`), and addressing (`&label`).

use nom::{
    branch::alt,
    bytes::complete::{tag, take_while, take_while1},
    character::complete::{char, digit1, hex_digit1, multispace0},
    combinator::{map, map_res, opt, peek, recognize, success, value},
    multi::{many0, many1, separated_list0},
    sequence::{delimited, pair, preceded, tuple},
    IResult,
};
use std::fmt;

// ===========================================================================
// Top-level AST types
// ===========================================================================

/// Endianness of the processor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Big,
    Little,
}

impl fmt::Display for Endian {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Endian::Big => write!(f, "big"),
            Endian::Little => write!(f, "little"),
        }
    }
}

/// A fully parsed `.slaspec` file.
#[derive(Debug, Clone)]
pub struct SlaspecFile {
    pub endian: Endian,
    pub alignment: u32,
    pub spaces: Vec<SpaceDefinition>,
    pub tokens: Vec<TokenDefinition>,
    pub context: Vec<ContextField>,
    pub registers: Vec<RegisterDefinition>,
    pub macros: Vec<MacroDefinition>,
    pub constructors: Vec<Constructor>,
    pub subconstructors: Vec<SubConstructor>,
    pub attached_registers: Vec<AttachedRegister>,
    pub pcode_macros: Vec<PcodeMacro>,
}

impl Default for SlaspecFile {
    fn default() -> Self {
        SlaspecFile {
            endian: Endian::Little,
            alignment: 1,
            spaces: Vec::new(),
            tokens: Vec::new(),
            context: Vec::new(),
            registers: Vec::new(),
            macros: Vec::new(),
            constructors: Vec::new(),
            subconstructors: Vec::new(),
            attached_registers: Vec::new(),
            pcode_macros: Vec::new(),
        }
    }
}

// ===========================================================================
// Definition types
// ===========================================================================

/// Memory space definition (`define space ...`).
#[derive(Debug, Clone)]
pub struct SpaceDefinition {
    pub name: String,
    pub space_type: SpaceType,
    pub size: u32,
    pub wordsize: u32,
    pub default_register: Option<String>,
}

/// Space types found in SLEIGH specifications.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpaceType {
    RamSpace,
    RegisterSpace,
    ConstantSpace,
    UniqueSpace,
}

impl fmt::Display for SpaceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpaceType::RamSpace => write!(f, "ram_space"),
            SpaceType::RegisterSpace => write!(f, "register_space"),
            SpaceType::ConstantSpace => write!(f, "constant_space"),
            SpaceType::UniqueSpace => write!(f, "unique_space"),
        }
    }
}

/// Token definition (`define token NAME (SIZE) ...`).
#[derive(Debug, Clone)]
pub struct TokenDefinition {
    pub name: String,
    pub size: u32,
    pub fields: Vec<TokenFieldDefinition>,
}

/// A single field within a token.
#[derive(Debug, Clone)]
pub struct TokenFieldDefinition {
    pub name: String,
    pub start: u32,
    pub end: u32,
    pub is_signed: bool,
    pub is_decoded: bool,
}

/// Context variable field definition.
#[derive(Debug, Clone)]
pub struct ContextField {
    pub name: String,
    pub start: u32,
    pub end: u32,
    pub is_flow: bool,
    pub default_value: Option<u64>,
}

/// Register definition (`define register offset=... size=... [ ... ]`).
#[derive(Debug, Clone)]
pub struct RegisterDefinition {
    pub name: String,
    pub size: u32,
    pub offset: u64,
    pub parent: Option<String>,
    pub slice: Option<(u32, u32)>,
}

/// Macro definition (`macro NAME(PARAMS) { ... }`).
#[derive(Debug, Clone)]
pub struct MacroDefinition {
    pub name: String,
    pub parameters: Vec<String>,
    pub body: Vec<MacroStatement>,
}

/// A statement inside a macro body.
#[derive(Debug, Clone)]
pub enum MacroStatement {
    Assign {
        dest: String,
        src: String,
    },
    Build {
        template: String,
        params: Vec<String>,
    },
    If {
        condition: String,
        then_body: Vec<MacroStatement>,
        else_body: Option<Vec<MacroStatement>>,
    },
    Call {
        name: String,
        args: Vec<String>,
    },
    Raw(String),
}

/// Attach variables definition.
#[derive(Debug, Clone)]
pub struct AttachedRegister {
    pub name: String,
    pub registers: Vec<String>,
    pub size: u32,
    pub wordsize: u32,
}

/// P-code macro (op) definition.
#[derive(Debug, Clone)]
pub struct PcodeMacro {
    pub name: String,
    pub parameters: Vec<String>,
    pub body: Vec<SemanticStatement>,
}

// ===========================================================================
// Constructor types
// ===========================================================================

/// A full constructor (instruction pattern with semantics).
#[derive(Debug, Clone)]
pub struct Constructor {
    pub table_name: Option<String>,
    pub header: ConstructorHeader,
    pub pattern: PatternExpr,
    pub display: DisplaySection,
    pub semantics: Vec<SemanticStatement>,
}

/// The header portion of a constructor.
#[derive(Debug, Clone)]
pub struct ConstructorHeader {
    pub mnemonic: String,
    pub operand_patterns: Vec<OperandPattern>,
    pub condition: Option<String>,
}

/// A named operand in the constructor header.
#[derive(Debug, Clone)]
pub struct OperandPattern {
    pub name: String,
    pub constraint: OperandConstraint,
}

/// Constraints on what an operand can match.
#[derive(Debug, Clone)]
pub enum OperandConstraint {
    Any,
    Sized { min: u32, max: u32 },
    Register(String),
    RegisterList(Vec<String>),
    NumberRange { min: i64, max: i64 },
    Equals(String),
    NotEquals(String),
}

/// The display / equation section of a constructor.
#[derive(Debug, Clone)]
pub struct DisplaySection {
    pub format: String,
}

/// A sub-constructor (pattern-only, no semantics).
#[derive(Debug, Clone)]
pub struct SubConstructor {
    pub table_name: Option<String>,
    pub header: ConstructorHeader,
    pub pattern: PatternExpr,
}

// ===========================================================================
// Pattern expression types
// ===========================================================================

/// A constructor pattern expression tree.
#[derive(Debug, Clone)]
pub enum PatternExpr {
    /// A single field-value equation: `fieldname = value`.
    FieldValue { field: String, value: PatternValue },
    /// A reference to another table / sub-constructor.
    TableRef(String),
    /// The `...` ellipsis (instruction boundary marker).
    Ellipsis,
    /// Logical AND of two pattern expressions.
    And(Box<PatternExpr>, Box<PatternExpr>),
    /// Logical OR of two pattern expressions.
    Or(Box<PatternExpr>, Box<PatternExpr>),
    /// Negation / not-equal constraint: `field != value`.
    NotEqual { field: String, value: PatternValue },
}

/// The right-hand side of a field equation in a pattern.
#[derive(Debug, Clone)]
pub enum PatternValue {
    /// An integer constant (decimal, hex `0x...`, binary `0b...`).
    Constant(u64),
    /// An identifier (register name, etc.).
    Ident(String),
    /// A nested parenthesized pattern expression.
    Expr(Box<PatternExpr>),
}

// ===========================================================================
// Semantic statement types
// ===========================================================================

/// A varnode expression: `*:size offset` or `*[space]:size offset`.
#[derive(Debug, Clone)]
pub struct VarnodeExpr {
    pub space: Option<String>,
    pub size: u32,
    pub offset: Box<Expression>,
}

/// A statement within a constructor's semantic section.
#[derive(Debug, Clone)]
pub enum SemanticStatement {
    /// `export` size and value.
    Export { size: u32, value: Box<Expression> },
    /// Assignment: `dest = src;`
    Assign {
        dest: Box<Expression>,
        src: Box<Expression>,
    },
    /// Memory store: `*:size offset = src;`
    Store {
        varnode: VarnodeExpr,
        src: Box<Expression>,
    },
    /// `local name:size = init;` or `local name:size;`
    LocalVar {
        name: String,
        size: u32,
        init: Option<Box<Expression>>,
    },
    /// `build name;` - invoke a sub-constructor.
    Build { name: String },
    /// `goto label;` or `goto [expr];`
    Goto { target: Box<Expression> },
    /// `if (cond) goto label;`
    IfGoto {
        condition: Box<Expression>,
        target: Box<Expression>,
    },
    /// `call target;`
    Call { target: Box<Expression> },
    /// `return [target];` or `return;`
    Return { target: Option<Box<Expression>> },
    /// A macro or function call: `name(args);`
    MacroCall { name: String, args: Vec<Expression> },
    /// Empty statement (just `;`).
    Nop,
}

// ===========================================================================
// Expression types
// ===========================================================================

/// An expression appearing in semantic sections and equations.
#[derive(Debug, Clone)]
pub enum Expression {
    /// A simple identifier (register name, local variable, label).
    Identifier(String),
    /// An integer literal.
    Number(u64),
    /// Unary operator applied to an expression.
    UnaryOp {
        op: UnaryOperator,
        expr: Box<Expression>,
    },
    /// Binary operator applied to two expressions.
    BinaryOp {
        op: BinaryOperator,
        left: Box<Expression>,
        right: Box<Expression>,
    },
    /// Field extraction: `expr[start, end]`.
    FieldExtract {
        value: Box<Expression>,
        start: Box<Expression>,
        end: Box<Expression>,
    },
    /// Varnode dereference: `*:size offset` or `*[space]:size offset`.
    Varnode(VarnodeExpr),
    /// Address-of: `&expr`.
    AddressOf(Box<Expression>),
    /// Function call: `name(args)`.
    FunctionCall { name: String, args: Vec<Expression> },
}

/// Unary operators used in SLEIGH expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOperator {
    Neg,
    BitNot,
    LogicalNot,
}

impl fmt::Display for UnaryOperator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnaryOperator::Neg => write!(f, "-"),
            UnaryOperator::BitNot => write!(f, "~"),
            UnaryOperator::LogicalNot => write!(f, "!"),
        }
    }
}

/// Binary operators used in SLEIGH expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOperator {
    Add,
    Sub,
    Mul,
    Div,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    // Signed shift right
    SShr,
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    // Signed comparisons
    SLess,
    SLessEqual,
    SGreater,
    SGreaterEqual,
}

impl fmt::Display for BinaryOperator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BinaryOperator::Add => write!(f, "+"),
            BinaryOperator::Sub => write!(f, "-"),
            BinaryOperator::Mul => write!(f, "*"),
            BinaryOperator::Div => write!(f, "/"),
            BinaryOperator::And => write!(f, "&"),
            BinaryOperator::Or => write!(f, "|"),
            BinaryOperator::Xor => write!(f, "^"),
            BinaryOperator::Shl => write!(f, "<<"),
            BinaryOperator::Shr => write!(f, ">>"),
            BinaryOperator::SShr => write!(f, "s>>"),
            BinaryOperator::Equal => write!(f, "=="),
            BinaryOperator::NotEqual => write!(f, "!="),
            BinaryOperator::Less => write!(f, "<"),
            BinaryOperator::LessEqual => write!(f, "<="),
            BinaryOperator::Greater => write!(f, ">"),
            BinaryOperator::GreaterEqual => write!(f, ">="),
            BinaryOperator::SLess => write!(f, "s<"),
            BinaryOperator::SLessEqual => write!(f, "s<="),
            BinaryOperator::SGreater => write!(f, "s>"),
            BinaryOperator::SGreaterEqual => write!(f, "s>="),
        }
    }
}

// ===========================================================================
// Helper parsers: whitespace, comments, numbers, identifiers
// ===========================================================================

/// Skip whitespace and line comments (`#` to end of line).
fn ws(input: &str) -> IResult<&str, ()> {
    let mut remaining = input;
    loop {
        let before = remaining;
        // Skip whitespace
        let (r, _) = multispace0(remaining)?;
        remaining = r;
        // Skip line comment: `#` to newline or EOF
        if remaining.starts_with('#') {
            let (r, _) = preceded(char('#'), take_while(|c: char| c != '\n' && c != '\r'))(remaining)?;
            remaining = r;
        }
        if remaining.len() == before.len() {
            break;
        }
    }
    Ok((remaining, ()))
}

/// Parse something surrounded by optional whitespace.
fn token<'a, F: 'a, O>(inner: F) -> impl FnMut(&'a str) -> IResult<&'a str, O>
where
    F: FnMut(&'a str) -> IResult<&'a str, O>,
{
    delimited(ws, inner, ws)
}

/// Parse an identifier: `[a-zA-Z_][a-zA-Z0-9_]*`
fn identifier(input: &str) -> IResult<&str, String> {
    let (input, id) = recognize(pair(
        take_while1(|c: char| c.is_ascii_alphabetic() || c == '_'),
        take_while(|c: char| c.is_ascii_alphanumeric() || c == '_'),
    ))(input)?;
    // Exclude keywords that could be parsed as identifiers
    let kw = id;
    if kw == "define"
        || kw == "endian"
        || kw == "alignment"
        || kw == "space"
        || kw == "type"
        || kw == "ram_space"
        || kw == "register_space"
        || kw == "constant_space"
        || kw == "unique_space"
        || kw == "register"
        || kw == "token"
        || kw == "is"
        || kw == "context"
        || kw == "macro"
        || kw == "pcodeop"
        || kw == "attach"
        || kw == "variables"
        || kw == "with"
        || kw == "is"
        || kw == "local"
        || kw == "export"
        || kw == "build"
        || kw == "goto"
        || kw == "if"
        || kw == "call"
        || kw == "return"
        || kw == "default"
        || kw == "signed"
        || kw == "decoded"
        || kw == "noflow"
        || kw == "wordsize"
        || kw == "offset"
        || kw == "size"
    {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )));
    }
    Ok((input, id.to_string()))
}

/// Parse a string identifier: `[a-zA-Z_][a-zA-Z0-9_]*` including space type keywords.
fn identifier_or_keyword(input: &str) -> IResult<&str, String> {
    map(
        recognize(pair(
            take_while1(|c: char| c.is_ascii_alphabetic() || c == '_'),
            take_while(|c: char| c.is_ascii_alphanumeric() || c == '_'),
        )),
        |s: &str| s.to_string(),
    )(input)
}

/// Parse a decimal integer.
fn decimal_integer(input: &str) -> IResult<&str, u64> {
    map_res(digit1, |s: &str| u64::from_str_radix(s, 10))(input)
}

/// Parse a hexadecimal integer: `0x[0-9a-fA-F]+` or `x[0-9a-fA-F]+`
fn hex_integer(input: &str) -> IResult<&str, u64> {
    let (input, _) = alt((tag("0x"), tag("0X"), tag("x"), tag("X")))(input)?;
    let (input, digits) = hex_digit1(input)?;
    let val = u64::from_str_radix(digits, 16).map_err(|_| {
        nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::MapRes))
    })?;
    Ok((input, val))
}

/// Parse a binary integer: `0b[01]+`
fn bin_integer(input: &str) -> IResult<&str, u64> {
    let (input, _) = alt((tag("0b"), tag("0B")))(input)?;
    let (input, digits) = take_while1(|c: char| c == '0' || c == '1')(input)?;
    let val = u64::from_str_radix(digits, 2).map_err(|_| {
        nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::MapRes))
    })?;
    Ok((input, val))
}

/// Parse any integer literal (hex, binary, or decimal).
fn integer(input: &str) -> IResult<&str, u64> {
    alt((hex_integer, bin_integer, decimal_integer))(input)
}

/// Parse a string literal: `"..."`  (used in quoted mnemonics like `"NZ"`)
fn string_literal(input: &str) -> IResult<&str, String> {
    let (input, _) = char('"')(input)?;
    let (input, s) = take_while(|c: char| c != '"')(input)?;
    let (input, _) = char('"')(input)?;
    Ok((input, s.to_string()))
}

/// A quoted mnemonic like `"NZ"` used in some constructors.
fn quoted_mnemonic(input: &str) -> IResult<&str, String> {
    string_literal(input)
}

/// Parse a mnemonic: either a bare identifier or a quoted string.
fn mnemonic(input: &str) -> IResult<&str, String> {
    alt((quoted_mnemonic, identifier))(input)
}

/// Parse a required semicolon.
fn semicolon(input: &str) -> IResult<&str, ()> {
    let (input, _) = token(char(';'))(input)?;
    Ok((input, ()))
}

// ===========================================================================
// Define statement parsers
// ===========================================================================

/// Parse `define endian=little;` or `define endian=big;`
fn parse_endian(input: &str) -> IResult<&str, Endian> {
    let (input, _) = token(tag("define"))(input)?;
    let (input, _) = token(tag("endian"))(input)?;
    let (input, _) = token(char('='))(input)?;
    let (input, value) = token(alt((
        value(Endian::Little, tag("little")),
        value(Endian::Big, tag("big")),
    )))(input)?;
    let (input, _) = semicolon(input)?;
    Ok((input, value))
}

/// Parse `define alignment=N;`
fn parse_alignment(input: &str) -> IResult<&str, u32> {
    let (input, _) = token(tag("define"))(input)?;
    let (input, _) = token(tag("alignment"))(input)?;
    let (input, _) = token(char('='))(input)?;
    let (input, val) = token(integer)(input)?;
    let (input, _) = semicolon(input)?;
    Ok((input, val as u32))
}

/// Parse `define space NAME type=TYPE [wordsize=N] size=N [default];`
fn parse_space(input: &str) -> IResult<&str, SpaceDefinition> {
    let (input, _) = token(tag("define"))(input)?;
    let (input, _) = token(tag("space"))(input)?;
    let (input, name) = token(identifier_or_keyword)(input)?;
    let (input, _) = token(tag("type"))(input)?;
    let (input, _) = token(char('='))(input)?;
    let (input, space_type) = token(alt((
        value(SpaceType::RamSpace, tag("ram_space")),
        value(SpaceType::RegisterSpace, tag("register_space")),
        value(SpaceType::ConstantSpace, tag("constant_space")),
        value(SpaceType::UniqueSpace, tag("unique_space")),
    )))(input)?;
    // Optional wordsize
    let (input, wordsize) = opt(|i| {
        let (i, _) = token(tag("wordsize"))(i)?;
        let (i, _) = token(char('='))(i)?;
        token(integer)(i)
    })(input)?;
    let (input, _) = token(tag("size"))(input)?;
    let (input, _) = token(char('='))(input)?;
    let (input, size) = token(integer)(input)?;
    let (input, _default) = opt(token(tag("default")))(input)?;
    let (input, _) = semicolon(input)?;
    Ok((
        input,
        SpaceDefinition {
            name,
            space_type,
            size: size as u32,
            wordsize: wordsize.unwrap_or(1) as u32,
            default_register: None,
        },
    ))
}

/// Parse `define register offset=HEX size=N [ REG1 REG2 ... ];`
fn parse_register(input: &str) -> IResult<&str, Vec<RegisterDefinition>> {
    let (input, _) = token(tag("define"))(input)?;
    let (input, _) = token(tag("register"))(input)?;
    let (input, _) = token(tag("offset"))(input)?;
    let (input, _) = token(char('='))(input)?;
    let (input, offset) = token(integer)(input)?;
    let (input, _) = token(tag("size"))(input)?;
    let (input, _) = token(char('='))(input)?;
    let (input, size) = token(integer)(input)?;
    // Register list in brackets: [ NAME NAME ... ]
    let (input, names) =
        delimited(token(char('[')), many1(token(identifier)), token(char(']')))(input)?;
    let (input, _) = semicolon(input)?;
    let regs: Vec<RegisterDefinition> = names
        .into_iter()
        .map(|name| RegisterDefinition {
            name,
            size: size as u32,
            offset,
            parent: None,
            slice: None,
        })
        .collect();
    Ok((input, regs))
}

/// Parse a token field: `name = (start, end) [signed] [decoded]`
fn parse_token_field(input: &str) -> IResult<&str, TokenFieldDefinition> {
    let (input, name) = token(identifier)(input)?;
    let (input, _) = token(char('='))(input)?;
    let (input, _) = token(char('('))(input)?;
    let (input, start) = token(integer)(input)?;
    let (input, _) = token(char(','))(input)?;
    let (input, end) = token(integer)(input)?;
    let (input, _) = token(char(')'))(input)?;
    let (input, is_signed) = map(opt(token(tag("signed"))), |o| o.is_some())(input)?;
    let (input, is_decoded) = map(opt(token(tag("decoded"))), |o| o.is_some())(input)?;
    Ok((
        input,
        TokenFieldDefinition {
            name,
            start: start as u32,
            end: end as u32,
            is_signed,
            is_decoded,
        },
    ))
}

/// Parse `define token NAME (SIZE) field1 field2 ... ;`
fn parse_token(input: &str) -> IResult<&str, TokenDefinition> {
    let (input, _) = token(tag("define"))(input)?;
    let (input, _) = token(tag("token"))(input)?;
    let (input, name) = token(identifier)(input)?;
    let (input, _) = token(char('('))(input)?;
    let (input, size) = token(integer)(input)?;
    let (input, _) = token(char(')'))(input)?;
    let (input, fields) = many0(parse_token_field)(input)?;
    let (input, _) = semicolon(input)?;
    Ok((
        input,
        TokenDefinition {
            name,
            size: size as u32,
            fields,
        },
    ))
}

/// Parse a single context field: `NAME = (START, END) [noflow] [default=VAL]`
fn parse_context_field(input: &str) -> IResult<&str, ContextField> {
    let (input, name) = token(identifier)(input)?;
    let (input, _) = token(char('='))(input)?;
    let (input, _) = token(char('('))(input)?;
    let (input, start) = token(integer)(input)?;
    let (input, _) = token(char(','))(input)?;
    let (input, end) = token(integer)(input)?;
    let (input, _) = token(char(')'))(input)?;
    // noflow means is_flow = false (flow tracking disabled); default is flow tracking on
    let (input, noflow) = map(opt(token(tag("noflow"))), |o| o.is_some())(input)?;
    // Optional default value
    let (input, default_value) = opt(preceded(
        token(tag("default")),
        preceded(token(char('=')), token(integer)),
    ))(input)?;
    Ok((
        input,
        ContextField {
            name,
            start: start as u32,
            end: end as u32,
            is_flow: !noflow,
            default_value,
        },
    ))
}

/// Parse `define context REGNAME field1 field2 ... ;`
fn parse_context(input: &str) -> IResult<&str, Vec<ContextField>> {
    let (input, _) = token(tag("define"))(input)?;
    let (input, _) = token(tag("context"))(input)?;
    let (input, _reg_name) = token(identifier)(input)?;
    let (input, fields) = many0(parse_context_field)(input)?;
    let (input, _) = semicolon(input)?;
    Ok((input, fields))
}

/// Parse `define pcodeop NAME;`
fn parse_pcodeop(input: &str) -> IResult<&str, PcodeMacro> {
    let (input, _) = token(tag("define"))(input)?;
    let (input, _) = token(tag("pcodeop"))(input)?;
    let (input, name) = token(identifier)(input)?;
    let (input, params) = opt(delimited(
        token(char('(')),
        separated_list0(token(char(',')), token(identifier)),
        token(char(')')),
    ))(input)?;
    let (input, _) = semicolon(input)?;
    Ok((
        input,
        PcodeMacro {
            name,
            parameters: params.unwrap_or_default(),
            body: vec![],
        },
    ))
}

/// Parse `attach variables [ FIELDS ] [ REGISTERS ];`
fn parse_attach(input: &str) -> IResult<&str, AttachedRegister> {
    let (input, _) = token(tag("attach"))(input)?;
    let (input, _) = token(tag("variables"))(input)?;
    let (input, fields) =
        delimited(token(char('[')), many1(token(identifier)), token(char(']')))(input)?;
    let (input, registers) =
        delimited(token(char('[')), many1(token(identifier)), token(char(']')))(input)?;
    let (input, _) = semicolon(input)?;

    // We produce one AttachedRegister per register listed (all same fields).
    // The `name` is the register name.
    let attached: Vec<AttachedRegister> = registers
        .into_iter()
        .map(|reg| AttachedRegister {
            name: reg,
            registers: fields.clone(),
            size: 0,
            wordsize: 0,
        })
        .collect();

    // Return just the first one; the caller should handle multiple.
    // We'll collect them in parse_slaspec.
    // Actually, let's return the list; the caller aggregates.
    Ok((input, attached.into_iter().next().unwrap()))
}

// ===========================================================================
// Macro parsers
// ===========================================================================

/// Parse a macro statement. Macro bodies are mostly free-form text with
/// SLEIGH-like statements, but we parse them structurally where possible.
fn parse_macro_statement(input: &str) -> IResult<&str, MacroStatement> {
    alt((
        parse_macro_if,
        parse_macro_build,
        parse_macro_call,
        parse_macro_assign,
        parse_macro_raw,
    ))(input)
}

fn parse_macro_if(input: &str) -> IResult<&str, MacroStatement> {
    let (input, _) = token(tag("if"))(input)?;
    let (input, _) = token(char('('))(input)?;
    let (input, condition) = take_while(|c: char| c != ')')(input)?;
    let (input, _) = token(char(')'))(input)?;
    // Try to parse block form first
    let res: IResult<&str, _> = delimited(
        token(char('{')),
        many0(parse_macro_statement),
        token(char('}')),
    )(input);
    if let Ok((input, then_body)) = res {
        let (input, else_body) = opt(preceded(
            token(tag("else")),
            delimited(
                token(char('{')),
                many0(parse_macro_statement),
                token(char('}')),
            ),
        ))(input)?;
        return Ok((
            input,
            MacroStatement::If {
                condition: condition.to_string(),
                then_body,
                else_body,
            },
        ));
    }
    // Single-line form: if (cond) stmt;
    let (input, rest) = token(take_while(|c: char| c != ';'))(input)?;
    let (input, _) = semicolon(input)?;
    Ok((
        input,
        MacroStatement::Raw(format!("if ({}) {}", condition, rest)),
    ))
}

fn parse_macro_build(input: &str) -> IResult<&str, MacroStatement> {
    let (input, _) = token(tag("build"))(input)?;
    let (input, template) = token(identifier)(input)?;
    let (input, params) = opt(delimited(
        token(char('(')),
        separated_list0(
            token(char(',')),
            map(token(identifier_or_keyword), String::from),
        ),
        token(char(')')),
    ))(input)?;
    let (input, _) = semicolon(input)?;
    Ok((
        input,
        MacroStatement::Build {
            template,
            params: params.unwrap_or_default(),
        },
    ))
}

fn parse_macro_call(input: &str) -> IResult<&str, MacroStatement> {
    let (input, name) = token(identifier)(input)?;
    let (input, _) = token(char('('))(input)?;
    let (input, args) = separated_list0(
        token(char(',')),
        map(
            take_while(|c: char| c != ',' && c != ')' && c != ';'),
            |s: &str| s.trim().to_string(),
        ),
    )(input)?;
    let (input, _) = token(char(')'))(input)?;
    let (input, _) = semicolon(input)?;
    Ok((
        input,
        MacroStatement::Call {
            name,
            args: args.into_iter().filter(|s| !s.is_empty()).collect(),
        },
    ))
}

fn parse_macro_assign(input: &str) -> IResult<&str, MacroStatement> {
    // Peek the entire pattern to avoid consuming input on failure
    // (identifier '=' <non-semicolon chars> ';')
    // This prevents nom's alt() from failing due to partial consumption.
    let _ = peek(tuple((
        token(identifier),
        token(char('=')),
        take_while(|c: char| c != ';'),
        token(char(';')),
    )))(input)?;

    // Pattern matched -- now parse for real
    let (input, dest) = token(identifier)(input)?;
    let (input, _) = token(char('='))(input)?;
    let (input, src) = take_while(|c: char| c != ';')(input)?;
    let (input, _) = semicolon(input)?;
    Ok((
        input,
        MacroStatement::Assign {
            dest,
            src: src.trim().to_string(),
        },
    ))
}

fn parse_macro_raw(input: &str) -> IResult<&str, MacroStatement> {
    // Catch-all: everything up to semicolon
    let (input, raw) = token(take_while(|c: char| c != ';'))(input)?;
    let (input, _) = semicolon(input)?;
    Ok((input, MacroStatement::Raw(raw.trim().to_string())))
}

/// Parse `macro NAME ( PARAMS ) { BODY }`
fn parse_macro(input: &str) -> IResult<&str, MacroDefinition> {
    let (input, _) = token(tag("macro"))(input)?;
    let (input, name) = token(identifier)(input)?;
    let (input, _) = token(char('('))(input)?;
    let (input, params) = separated_list0(token(char(',')), token(identifier))(input)?;
    let (input, _) = token(char(')'))(input)?;
    let (input, body) = delimited(
        token(char('{')),
        many0(parse_macro_statement),
        token(char('}')),
    )(input)?;
    Ok((
        input,
        MacroDefinition {
            name,
            parameters: params,
            body,
        },
    ))
}

// ===========================================================================
// Pattern expression parsers
// ===========================================================================

/// Parse a `...` ellipsis (instruction boundary marker).
fn pattern_ellipsis(input: &str) -> IResult<&str, PatternExpr> {
    map(token(tag("...")), |_| PatternExpr::Ellipsis)(input)
}

/// Parse a constant value (integer).
fn pattern_constant(input: &str) -> IResult<&str, PatternValue> {
    map(token(integer), PatternValue::Constant)(input)
}

/// Parse a parenthesized pattern expression as a value.
fn pattern_value_expr(input: &str) -> IResult<&str, PatternValue> {
    map(
        delimited(token(char('(')), parse_pattern_expression, token(char(')'))),
        |e| PatternValue::Expr(Box::new(e)),
    )(input)
}

/// Parse the right-hand side of a pattern equation.
fn pattern_value(input: &str) -> IResult<&str, PatternValue> {
    alt((
        pattern_value_expr,
        pattern_constant,
        map(token(identifier), PatternValue::Ident),
    ))(input)
}

/// Parse a field equation: `fieldname = value`
fn pattern_equation(input: &str) -> IResult<&str, PatternExpr> {
    let (input, field) = token(identifier_or_keyword)(input)?;
    let (input, _eq) = token(char('='))(input)?;
    let res = pattern_value(input);
    match res {
        Ok((input, value)) => Ok((input, PatternExpr::FieldValue { field, value })),
        Err(_) => {
            // If the value doesn't parse, this might be a table reference
            // (an identifier that happens to come before something else).
            // Reject - return error.
            Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Tag,
            )))
        }
    }
}

/// Parse a table reference: just an identifier not followed by `=`.
fn pattern_table_ref(input: &str) -> IResult<&str, PatternExpr> {
    let (input, id) = token(identifier)(input)?;
    // Peek to make sure it's NOT followed by =
    let (peek_input, _) = ws(input)?;
    if peek_input.starts_with('=') && !peek_input.starts_with("==") {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )));
    }
    Ok((input, PatternExpr::TableRef(id)))
}

/// Parse a pattern factor (atom or parenthesized group).
fn pattern_factor(input: &str) -> IResult<&str, PatternExpr> {
    alt((
        pattern_ellipsis,
        // Parenthesized pattern expression
        delimited(token(char('(')), parse_pattern_expression, token(char(')'))),
        pattern_equation,
        pattern_table_ref,
    ))(input)
}

/// Parse a pattern term (factors joined by `&`, with optional implicit AND).
fn pattern_term(input: &str) -> IResult<&str, PatternExpr> {
    let (mut input, mut first) = pattern_factor(input)?;
    // When an ellipsis (`...`) is encountered before an explicit `&`, it is
    // deferred and combined with the *right* side of the `&`.  This produces
    // `op=0x90 ... & REL` => `And(FieldValue{op}, And(Ellipsis, TableRef))`
    // rather than `And(And(FieldValue{op}, Ellipsis), TableRef)`.
    let mut pending_ellipsis = false;

    loop {
        // Skip whitespace first, then check for `...`, explicit `&`, or implicit AND.
        let (after_ws, _) = multispace0(input)?;

        // Consume a standalone `...` and defer it.
        if let Ok((rest, _)) = tag::<&str, &str, nom::error::Error<&str>>("...")(after_ws) {
            input = rest;
            pending_ellipsis = true;
            continue;
        }

        // Try explicit `&` first.
        let amp: IResult<&str, char> = char('&')(after_ws);
        if let Ok((rest, _)) = amp {
            input = rest;
            let (rest, next) = pattern_factor(input)?;
            input = rest;
            if pending_ellipsis {
                // Wrap the deferred ellipsis with the right operand: ... AND next
                let right = PatternExpr::And(Box::new(PatternExpr::Ellipsis), Box::new(next));
                first = PatternExpr::And(Box::new(first), Box::new(right));
                pending_ellipsis = false;
            } else {
                first = PatternExpr::And(Box::new(first), Box::new(next));
            }
            continue;
        }
        // Try implicit AND: the next token is a pattern factor (not `{` or end of input).
        if !after_ws.is_empty() && !after_ws.starts_with('{') && !after_ws.starts_with('}') {
            if let Ok((rest, next)) = pattern_factor(after_ws) {
                input = rest;
                if pending_ellipsis {
                    let right = PatternExpr::And(Box::new(PatternExpr::Ellipsis), Box::new(next));
                    first = PatternExpr::And(Box::new(first), Box::new(right));
                    pending_ellipsis = false;
                } else {
                    first = PatternExpr::And(Box::new(first), Box::new(next));
                }
                continue;
            }
        }
        break;
    }
    // If `...` appeared but was never followed by another factor, combine it
    // with the left side (normal left-associative grouping).
    if pending_ellipsis {
        first = PatternExpr::And(Box::new(first), Box::new(PatternExpr::Ellipsis));
    }
    Ok((input, first))
}

/// Parse a full pattern expression (terms joined by `|`).
fn parse_pattern_expression(input: &str) -> IResult<&str, PatternExpr> {
    let (mut input, mut first) = pattern_term(input)?;
    loop {
        let (after_ws, _) = multispace0(input)?;
        match char::<&str, nom::error::Error<&str>>('|')(after_ws) {
            Ok((rest, _)) => {
                input = rest;
                let (rest, next) = pattern_term(input)?;
                input = rest;
                first = PatternExpr::Or(Box::new(first), Box::new(next));
            }
            Err(_) => break,
        }
    }
    Ok((input, first))
}

// ===========================================================================
// Expression parsers (for semantic sections and equations)
// ===========================================================================

/// Parse a varnode: `*:size offset` or `*[space]:size offset`
fn parse_varnode(input: &str) -> IResult<&str, VarnodeExpr> {
    let (input, _) = token(char('*'))(input)?;
    // Optional space: `[space]`
    let (input, space) = opt(delimited(
        token(char('[')),
        token(identifier),
        token(char(']')),
    ))(input)?;
    let (input, _) = token(char(':'))(input)?;
    let (input, size) = token(integer)(input)?;
    let (input, offset) = parse_expression_inner(input)?;
    Ok((
        input,
        VarnodeExpr {
            space,
            size: size as u32,
            offset: Box::new(offset),
        },
    ))
}

/// Parse a function call: `name(args)` or `name()`
fn parse_function_call(input: &str) -> IResult<&str, Expression> {
    let (input, name) = token(identifier)(input)?;
    let (input, _) = token(char('('))(input)?;
    let (input, args) = separated_list0(token(char(',')), parse_expression)(input)?;
    let (input, _) = token(char(')'))(input)?;
    Ok((input, Expression::FunctionCall { name, args }))
}

/// Parse a primary expression atom.
fn parse_primary(input: &str) -> IResult<&str, Expression> {
    alt((
        // Parenthesized expression
        map(
            delimited(token(char('(')), parse_expression, token(char(')'))),
            |e| e,
        ),
        // Varnode dereference: *:size expr or *[space]:size expr
        map(parse_varnode, Expression::Varnode),
        // Address-of: &expr
        map(preceded(token(char::<&str, nom::error::Error<&str>>('&')), parse_primary), |e| {
            Expression::AddressOf(Box::new(e))
        }),
        // Function call: name(args)
        parse_function_call,
        // Integer literal
        map(token(integer), Expression::Number),
        // Identifier
        map(token(identifier), Expression::Identifier),
    ))(input)
}

/// Parse a unary expression.
fn parse_unary(input: &str) -> IResult<&str, Expression> {
    let (input, op) = opt(token(alt((
        value(UnaryOperator::Neg, char('-')),
        value(UnaryOperator::BitNot, char('~')),
        value(UnaryOperator::LogicalNot, char('!')),
    ))))(input)?;
    let (input, expr) = parse_postfix(input)?;
    match op {
        Some(op) => Ok((
            input,
            Expression::UnaryOp {
                op,
                expr: Box::new(expr),
            },
        )),
        None => Ok((input, expr)),
    }
}

/// Parse postfix operations: field extraction `expr[start, end]`
fn parse_postfix(input: &str) -> IResult<&str, Expression> {
    let (mut input, mut expr) = parse_primary(input)?;
    loop {
        // Try field extraction: [start, end]
        let res: IResult<&str, _> = delimited(
            token(char('[')),
            pair(
                parse_expression,
                preceded(token(char(',')), parse_expression),
            ),
            token(char(']')),
        )(input);
        match res {
            Ok((rest, (start, end))) => {
                input = rest;
                expr = Expression::FieldExtract {
                    value: Box::new(expr),
                    start: Box::new(start),
                    end: Box::new(end),
                };
            }
            Err(_) => {
                // Also try (start, end) - function call format for field extraction
                // This conflicts with function calls, so only try it if the expression
                // is an identifier (which means it's `reg(msb,lsb)` not `func(args)`)
                // Actually, field extraction uses [] notation; () is for function calls.
                break;
            }
        }
    }
    Ok((input, expr))
}

/// Parse a multiplicative expression: `*`, `/`
fn parse_multiplicative(input: &str) -> IResult<&str, Expression> {
    let (mut input, mut left) = parse_unary(input)?;
    loop {
        let res: IResult<&str, BinaryOperator> = token(alt((
            value(BinaryOperator::Mul, char('*')),
            value(BinaryOperator::Div, char('/')),
        )))(input);
        match res {
            Ok((rest, op)) => {
                let (rest, right) = parse_unary(rest)?;
                input = rest;
                left = Expression::BinaryOp {
                    op,
                    left: Box::new(left),
                    right: Box::new(right),
                };
            }
            Err(_) => break,
        }
    }
    Ok((input, left))
}

/// Parse an additive expression: `+`, `-`
fn parse_additive(input: &str) -> IResult<&str, Expression> {
    let (mut input, mut left) = parse_multiplicative(input)?;
    loop {
        let res: IResult<&str, BinaryOperator> = token(alt((
            value(BinaryOperator::Add, char('+')),
            value(BinaryOperator::Sub, char('-')),
        )))(input);
        match res {
            Ok((rest, op)) => {
                let (rest, right) = parse_multiplicative(rest)?;
                input = rest;
                left = Expression::BinaryOp {
                    op,
                    left: Box::new(left),
                    right: Box::new(right),
                };
            }
            Err(_) => break,
        }
    }
    Ok((input, left))
}

/// Parse a shift expression: `<<`, `>>`, `s>>`
fn parse_shift(input: &str) -> IResult<&str, Expression> {
    let (mut input, mut left) = parse_additive(input)?;
    loop {
        let res: IResult<&str, BinaryOperator> = token(alt((
            value(BinaryOperator::Shl, tag("<<")),
            value(BinaryOperator::SShr, tag("s>>")),
            value(BinaryOperator::Shr, tag(">>")),
        )))(input);
        match res {
            Ok((rest, op)) => {
                let (rest, right) = parse_additive(rest)?;
                input = rest;
                left = Expression::BinaryOp {
                    op,
                    left: Box::new(left),
                    right: Box::new(right),
                };
            }
            Err(_) => break,
        }
    }
    Ok((input, left))
}

/// Parse a comparison expression: `==`, `!=`, `<=`, `>=`, `<`, `>`, `s<=`, `s>=`, `s<`, `s>`
fn parse_comparison(input: &str) -> IResult<&str, Expression> {
    let (input, left) = parse_shift(input)?;
    let res: IResult<&str, BinaryOperator> = token(alt((
        value(BinaryOperator::Equal, tag("==")),
        value(BinaryOperator::NotEqual, tag("!=")),
        value(BinaryOperator::SLessEqual, tag("s<=")),
        value(BinaryOperator::SGreaterEqual, tag("s>=")),
        value(BinaryOperator::LessEqual, tag("<=")),
        value(BinaryOperator::GreaterEqual, tag(">=")),
        value(BinaryOperator::SLess, tag("s<")),
        value(BinaryOperator::SGreater, tag("s>")),
        value(BinaryOperator::Less, tag("<")),
        value(BinaryOperator::Greater, tag(">")),
    )))(input);
    match res {
        Ok((rest, op)) => {
            let (rest, right) = parse_shift(rest)?;
            Ok((
                rest,
                Expression::BinaryOp {
                    op,
                    left: Box::new(left),
                    right: Box::new(right),
                },
            ))
        }
        Err(_) => Ok((input, left)),
    }
}

/// Parse a bitwise AND expression: `&`
fn parse_bitwise_and(input: &str) -> IResult<&str, Expression> {
    let (mut input, mut left) = parse_comparison(input)?;
    loop {
        let res: IResult<&str, _> = token(char::<&str, nom::error::Error<&str>>('&'))(input);
        match res {
            Ok((rest, _)) => {
                let (rest, right) = parse_comparison(rest)?;
                input = rest;
                left = Expression::BinaryOp {
                    op: BinaryOperator::And,
                    left: Box::new(left),
                    right: Box::new(right),
                };
            }
            Err(_) => break,
        }
    }
    Ok((input, left))
}

/// Parse a bitwise XOR expression: `^`
fn parse_bitwise_xor(input: &str) -> IResult<&str, Expression> {
    let (mut input, mut left) = parse_bitwise_and(input)?;
    loop {
        let res: IResult<&str, _> = token(char('^'))(input);
        match res {
            Ok((rest, _)) => {
                let (rest, right) = parse_bitwise_and(rest)?;
                input = rest;
                left = Expression::BinaryOp {
                    op: BinaryOperator::Xor,
                    left: Box::new(left),
                    right: Box::new(right),
                };
            }
            Err(_) => break,
        }
    }
    Ok((input, left))
}

/// Parse a bitwise OR expression: `|`
fn parse_bitwise_or(input: &str) -> IResult<&str, Expression> {
    let (mut input, mut left) = parse_bitwise_xor(input)?;
    loop {
        let res: IResult<&str, _> = token(char::<&str, nom::error::Error<&str>>('|'))(input);
        match res {
            Ok((rest, _)) => {
                let (rest, right) = parse_bitwise_xor(rest)?;
                input = rest;
                left = Expression::BinaryOp {
                    op: BinaryOperator::Or,
                    left: Box::new(left),
                    right: Box::new(right),
                };
            }
            Err(_) => break,
        }
    }
    Ok((input, left))
}

/// Full expression parser with correct operator precedence.
///
/// Precedence (lowest to highest):
///   bitwise OR `|`  >  bitwise XOR `^`  >  bitwise AND `&`
///   >  comparison `== != < > <= >= s< s> s<= s>=`
///   >  shift `<< >> s>>`  >  addition `+ -`  >  multiplication `* /`
///   >  unary `- ~ !`  >  postfix `[ , ]`  >  primary
fn parse_expression_inner(input: &str) -> IResult<&str, Expression> {
    parse_bitwise_or(input)
}

// ===========================================================================
// Semantic statement parsers
// ===========================================================================

/// Parse an `export` statement.
fn parse_export_stmt(input: &str) -> IResult<&str, SemanticStatement> {
    let (input, _) = token(tag("export"))(input)?;
    // Check for varnode export: `export *:size expr;`
    let varnode_res: IResult<&str, VarnodeExpr> = parse_varnode(input);
    if let Ok((input, vn)) = varnode_res {
        let (input, _) = semicolon(input)?;
        return Ok((
            input,
            SemanticStatement::Export {
                size: vn.size,
                value: vn.offset,
            },
        ));
    }
    // Plain expression export: `export expr;`
    let (input, expr) = parse_expression_inner(input)?;
    let (input, _) = semicolon(input)?;
    Ok((
        input,
        SemanticStatement::Export {
            size: 0,
            value: Box::new(expr),
        },
    ))
}

/// Parse an assignment or store statement.
///
/// Uses `peek` to verify the pattern shape before consuming input, preventing
/// nom's `alt()` from getting stuck on a partial match.
fn parse_assign_stmt(input: &str) -> IResult<&str, SemanticStatement> {
    // Try varnode store first: `*:size offset = src;`
    if let Ok(_) = peek(tuple((
        parse_varnode,
        token(char('=')),
        take_while(|c: char| c != ';'),
        token(char(';')),
    )))(input)
    {
        let (input, vn) = parse_varnode(input)?;
        let (input, _) = token(char('='))(input)?;
        let (input, src) = parse_expression_inner(input)?;
        let (input, _) = semicolon(input)?;
        return Ok((
            input,
            SemanticStatement::Store {
                varnode: vn,
                src: Box::new(src),
            },
        ));
    }

    // Peek to verify the plain assignment shape:  expression '=' expression ';'
    // (not '==' -- the expression parser handles == internally for comparisons)
    let _ = peek(tuple((
        |i| parse_expression_inner(i),
        token(char('=')),
        take_while(|c: char| c != ';'),
        token(char(';')),
    )))(input)?;

    // Parse for real
    let (input, dest) = parse_expression_inner(input)?;
    let (input, _) = token(char('='))(input)?;
    let (input, src) = parse_expression_inner(input)?;
    let (input, _) = semicolon(input)?;
    Ok((
        input,
        SemanticStatement::Assign {
            dest: Box::new(dest),
            src: Box::new(src),
        },
    ))
}

/// Parse a `local` variable declaration.
fn parse_local_stmt(input: &str) -> IResult<&str, SemanticStatement> {
    let (input, _) = token(tag("local"))(input)?;
    let (input, name) = token(identifier)(input)?;
    let (input, _) = token(char(':'))(input)?;
    let (input, size) = token(integer)(input)?;
    let (input, init) = opt(preceded(token(char('=')), parse_expression))(input)?;
    let (input, _) = semicolon(input)?;
    Ok((
        input,
        SemanticStatement::LocalVar {
            name,
            size: size as u32,
            init: init.map(Box::new),
        },
    ))
}

/// Parse a `build` statement.
fn parse_build_stmt(input: &str) -> IResult<&str, SemanticStatement> {
    let (input, _) = token(tag("build"))(input)?;
    let (input, name) = token(identifier)(input)?;
    let (input, _) = semicolon(input)?;
    Ok((input, SemanticStatement::Build { name }))
}

/// Parse a `goto` statement.
fn parse_goto_stmt(input: &str) -> IResult<&str, SemanticStatement> {
    let (input, _) = token(tag("goto"))(input)?;
    // goto can take: identifier, [expr] (indirect), or just an expression
    let (input, target) = alt((
        // Indirect: goto [expr]
        map(
            delimited(token(char('[')), parse_expression, token(char(']'))),
            |e| e,
        ),
        // Direct: goto label or goto expr
        parse_expression,
    ))(input)?;
    let (input, _) = semicolon(input)?;
    Ok((
        input,
        SemanticStatement::Goto {
            target: Box::new(target),
        },
    ))
}

/// Parse an `if (cond) goto label;` statement.
fn parse_if_goto_stmt(input: &str) -> IResult<&str, SemanticStatement> {
    let (input, _) = token(tag("if"))(input)?;
    let (input, _) = token(char('('))(input)?;
    let (input, condition) = parse_expression_inner(input)?;
    let (input, _) = token(char(')'))(input)?;
    let (input, _) = token(tag("goto"))(input)?;
    let (input, target) = parse_expression_inner(input)?;
    let (input, _) = semicolon(input)?;
    Ok((
        input,
        SemanticStatement::IfGoto {
            condition: Box::new(condition),
            target: Box::new(target),
        },
    ))
}

/// Parse a `call` statement.
fn parse_call_stmt(input: &str) -> IResult<&str, SemanticStatement> {
    let (input, _) = token(tag("call"))(input)?;
    let (input, target) = parse_expression_inner(input)?;
    let (input, _) = semicolon(input)?;
    Ok((
        input,
        SemanticStatement::Call {
            target: Box::new(target),
        },
    ))
}

/// Parse a `return` statement.
fn parse_return_stmt(input: &str) -> IResult<&str, SemanticStatement> {
    let (input, _) = token(tag("return"))(input)?;
    let (input, target) = opt(delimited(
        token(char('[')),
        parse_expression,
        token(char(']')),
    ))(input)?;
    let (input, _) = semicolon(input)?;
    Ok((
        input,
        SemanticStatement::Return {
            target: target.map(Box::new),
        },
    ))
}

/// Parse a macro call in semantic context: `name();` or `name(args);`
///
/// Uses `peek` to avoid consuming the identifier on failure, which would
/// prevent nom's `alt()` from trying `parse_assign_stmt` as a fallback.
fn parse_macro_call_stmt(input: &str) -> IResult<&str, SemanticStatement> {
    // Peek to verify the shape: identifier '(' ... ')' ';'
    let _ = peek(tuple((
        token(identifier),
        token(char('(')),
        take_while(|c: char| c != ')' && c != ';'),
        token(char(')')),
        token(char(';')),
    )))(input)?;

    // Shape verified; parse for real
    let (input, name) = token(identifier)(input)?;
    let (input, _) = token(char('('))(input)?;
    let (input, args) = separated_list0(token(char(',')), parse_expression)(input)?;
    let (input, _) = token(char(')'))(input)?;
    let (input, _) = semicolon(input)?;
    Ok((input, SemanticStatement::MacroCall { name, args }))
}

/// Parse an empty statement: just `;`
fn parse_nop_stmt(input: &str) -> IResult<&str, SemanticStatement> {
    map(semicolon, |_| SemanticStatement::Nop)(input)
}

/// Parse a single semantic statement.
fn parse_semantic_stmt_inner(input: &str) -> IResult<&str, SemanticStatement> {
    alt((
        parse_if_goto_stmt,
        parse_export_stmt,
        parse_local_stmt,
        parse_build_stmt,
        parse_goto_stmt,
        parse_call_stmt,
        parse_return_stmt,
        parse_macro_call_stmt,
        parse_assign_stmt,
        parse_nop_stmt,
    ))(input)
}

/// Parse a block of semantic statements: `{ stmt1; stmt2; ... }`
fn parse_semantic_block(input: &str) -> IResult<&str, Vec<SemanticStatement>> {
    delimited(
        token(char('{')),
        many0(parse_semantic_stmt_inner),
        token(char('}')),
    )(input)
}

// ===========================================================================
// Constructor and sub-constructor parsers
// ===========================================================================

/// Parse a comma-separated list of operand patterns.
/// Parse an operand pattern name: an identifier or a numeric size constraint.
/// Unlike `identifier`, this allows pure numeric operands (e.g., `2` for size).
/// Unlike `identifier_or_keyword`, this excludes structural keywords like "is".
fn operand_name(input: &str) -> IResult<&str, String> {
    alt((
        map(token(identifier), |s| s),
        map(token(integer), |n| n.to_string()),
    ))(input)
}

fn parse_operand_list(input: &str) -> IResult<&str, Vec<OperandPattern>> {
    separated_list0(
        token(char(',')),
        map(operand_name, |name| OperandPattern {
            name,
            constraint: OperandConstraint::Any,
        }),
    )(input)
}

/// Parse the display / equation section: `[ equations ]` or `; format_string`
fn parse_display_section(input: &str) -> IResult<&str, DisplaySection> {
    alt((
        // Equation section: [ ... ]
        map(
            delimited(
                token(char('[')),
                take_while(|c: char| c != ']'),
                token(char(']')),
            ),
            |s: &str| DisplaySection {
                format: s.trim().to_string(),
            },
        ),
        // Just return empty if no display section
        map(success(()), |_| DisplaySection {
            format: String::new(),
        }),
    ))(input)
}

/// Parse the equation section for a sub-constructor (optional `[...]`).
fn parse_sub_equation_section(input: &str) -> IResult<&str, Option<DisplaySection>> {
    opt(map(
        delimited(
            token(char('[')),
            take_while(|c: char| c != ']'),
            token(char(']')),
        ),
        |s: &str| DisplaySection {
            format: s.trim().to_string(),
        },
    ))(input)
}

/// Parse a constructor: `[table_name:] mnemonic operands is pattern [equations] { semantics }`
fn parse_constructor_inner(input: &str) -> IResult<&str, Constructor> {
    // Optional table name followed by `:`
    let (input, table_name) = opt(|i| {
        let (i, id) = token(identifier)(i)?;
        let (i, _) = token(char(':'))(i)?;
        Ok((i, id))
    })(input)?;

    // Check for `:` prefix (root constructor without table name)
    let (input, root_prefix) = opt(token(char(':')))(input)?;

    // Mnemonic
    let (input, mnemonic) = token(mnemonic)(input)?;

    // Operands (optional, comma-separated)
    let (input, operands) = opt(parse_operand_list)(input)?;

    // `is` keyword
    let (input, _) = token(tag("is"))(input)?;

    // Pattern expression
    let (input, pattern) = parse_pattern_expression(input)?;

    // Display/equation section
    let (input, display) = parse_display_section(input)?;

    // Try to parse semantic block; if it fails, this might be a sub-constructor
    let (input, semantics) = parse_semantic_block(input)?;

    Ok((
        input,
        Constructor {
            table_name: if root_prefix.is_some() {
                None
            } else {
                table_name
            },
            header: ConstructorHeader {
                mnemonic,
                operand_patterns: operands.unwrap_or_default(),
                condition: None,
            },
            pattern,
            display,
            semantics,
        },
    ))
}

/// Parse a sub-constructor: `table_name : mnemonic operands is pattern [equations]`
/// (No semantic block -- a `{` after the pattern means this is a full constructor.)
fn parse_subconstructor(input: &str) -> IResult<&str, SubConstructor> {
    let (input, table_name) = token(identifier)(input)?;
    let (input, _) = token(char(':'))(input)?;
    let (input, mnemonic) = token(mnemonic)(input)?;
    let (input, operands) = opt(parse_operand_list)(input)?;
    let (input, _) = token(tag("is"))(input)?;
    let (input, pattern) = parse_pattern_expression(input)?;
    let (input, _display) = parse_sub_equation_section(input)?;

    // Reject if a semantic block follows (this is a full constructor, not a sub-constructor)
    let (peek, _) = ws(input)?;
    if peek.starts_with('{') {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )));
    }

    Ok((
        input,
        SubConstructor {
            table_name: Some(table_name),
            header: ConstructorHeader {
                mnemonic,
                operand_patterns: operands.unwrap_or_default(),
                condition: None,
            },
            pattern,
        },
    ))
}

// ===========================================================================
// With block parser
// ===========================================================================

/// Parse a `with : pattern_expr { constructors }` block.
/// Returns a list of constructors with the context pattern merged in.
fn parse_with_block(input: &str) -> IResult<&str, Vec<Constructor>> {
    let (input, _) = token(tag("with"))(input)?;
    let (input, _) = token(char(':'))(input)?;
    let (input, context_pattern) = parse_pattern_expression(input)?;
    let (input, constructors) = delimited(
        token(char('{')),
        many0(parse_top_level_constructor),
        token(char('}')),
    )(input)?;

    // Merge the context pattern into each constructor's pattern
    let merged = constructors
        .into_iter()
        .map(|mut c| {
            c.pattern = PatternExpr::And(Box::new(context_pattern.clone()), Box::new(c.pattern));
            c
        })
        .collect();

    Ok((input, merged))
}

/// Parse a single constructor (could be with-block or plain constructor).
fn parse_top_level_constructor(input: &str) -> IResult<&str, Constructor> {
    parse_constructor_inner(input)
}

// ===========================================================================
// Top-level definition parser (dispatcher)
// ===========================================================================

/// A single top-level definition in a .slaspec file.
#[derive(Debug, Clone)]
enum TopLevelDef {
    Endian(Endian),
    Alignment(u32),
    Space(SpaceDefinition),
    Registers(Vec<RegisterDefinition>),
    TokenDef(TokenDefinition),
    ContextFields(Vec<ContextField>),
    Attach(AttachedRegister),
    MacroDef(MacroDefinition),
    PcodeOp(PcodeMacro),
    ConstructorDef(Constructor),
    SubConstructorDef(SubConstructor),
    WithBlock(Vec<Constructor>),
}

/// Parse any single top-level definition.
///
/// Uses first-word peeking to dispatch, avoiding the backtracking issues
/// that arise when nom's `alt()` encounters partial matches.
fn parse_definition(input: &str) -> IResult<&str, Option<TopLevelDef>> {
    let (after_ws, _) = ws(input)?;
    if after_ws.is_empty() {
        return Ok((after_ws, None));
    }

    // Preprocessor directive
    if after_ws.starts_with('@') {
        return map(skip_preprocessor, |_| None)(input);
    }

    // Extract the first alphanumeric word for dispatch
    let first_word = after_ws
        .split(|c: char| c.is_whitespace() || c == ':' || c == '=')
        .next()
        .unwrap_or("");

    match first_word {
        "define" => {
            // All define sub-parsers start by consuming `define`; use alt for them
            alt((
                map(parse_endian, |e| Some(TopLevelDef::Endian(e))),
                map(parse_alignment, |a| Some(TopLevelDef::Alignment(a))),
                map(parse_space, |s| Some(TopLevelDef::Space(s))),
                map(parse_register, |r| Some(TopLevelDef::Registers(r))),
                map(parse_token, |t| Some(TopLevelDef::TokenDef(t))),
                map(parse_context, |c| Some(TopLevelDef::ContextFields(c))),
                map(parse_pcodeop, |p| Some(TopLevelDef::PcodeOp(p))),
            ))(input)
        }
        "attach" => map(parse_attach, |a| Some(TopLevelDef::Attach(a)))(input),
        "macro" => map(parse_macro, |m| Some(TopLevelDef::MacroDef(m)))(input),
        "with" => map(parse_with_block, |w| Some(TopLevelDef::WithBlock(w)))(input),
        _ => {
            // Could be a constructor or sub-constructor.
            // Peek to verify this looks like a constructor before committing.
            let shape_ok = peek(tuple((
                opt(pair(token(identifier_or_keyword), token(char(':')))),
                opt(token(char(':'))),
                token(identifier_or_keyword),
                take_while(|c: char| c != '\n' && c != '\r'),
            )))(input);

            match shape_ok {
                Ok(_) => {
                    // Looks like a constructor line -- try subconstructor first,
                    // then full constructor.
                    let sub: IResult<&str, SubConstructor> = parse_subconstructor(input);
                    match sub {
                        Ok((rest, sc)) => Ok((rest, Some(TopLevelDef::SubConstructorDef(sc)))),
                        Err(_) => {
                            map(parse_constructor, |c| Some(TopLevelDef::ConstructorDef(c)))(input)
                        }
                    }
                }
                Err(_) => {
                    // Not a recognized definition -- skip this line
                    let (input, _) = token(take_while(|c: char| c != '\n' && c != '\r'))(input)?;
                    Ok((input, None))
                }
            }
        }
    }
}

/// Skip include directives and other preprocessor lines.
fn skip_preprocessor(input: &str) -> IResult<&str, ()> {
    let (input, _) = token(char('@'))(input)?;
    let (input, _) = token(take_while(|c: char| c != '\n' && c != '\r'))(input)?;
    Ok((input, ()))
}

// ===========================================================================
// Main parser entry point
// ===========================================================================

/// Parse a complete `.slaspec` or `.sinc` file.
///
/// Returns a [`SlaspecFile`] containing all definitions found in the input.
/// Parsing is best-effort: unrecognised lines are skipped.
///
/// # Errors
///
/// Returns an error if the input contains fundamentally unparseable content
/// (the nom error will include the approximate position of the failure).
pub fn parse_slaspec(input: &str) -> Result<SlaspecFile, nom::Err<nom::error::Error<&str>>> {
    let mut result = SlaspecFile::default();
    let mut remaining = input;

    while !remaining.is_empty() {
        // Skip whitespace and comments
        let ws_res: IResult<&str, ()> = ws(remaining);
        match ws_res {
            Ok((rest, _)) => {
                remaining = rest;
            }
            Err(_) => break,
        }
        if remaining.is_empty() {
            break;
        }

        // Try to skip preprocessor directives
        if let Ok((rest, _)) = skip_preprocessor(remaining) {
            remaining = rest;
            continue;
        }

        // Try to parse a definition
        let def_res = parse_definition(remaining);
        match def_res {
            Ok((rest, Some(def))) => {
                remaining = rest;
                match def {
                    TopLevelDef::Endian(e) => result.endian = e,
                    TopLevelDef::Alignment(a) => result.alignment = a,
                    TopLevelDef::Space(s) => result.spaces.push(s),
                    TopLevelDef::Registers(regs) => result.registers.extend(regs),
                    TopLevelDef::TokenDef(t) => result.tokens.push(t),
                    TopLevelDef::ContextFields(cf) => result.context.extend(cf),
                    TopLevelDef::Attach(a) => result.attached_registers.push(a),
                    TopLevelDef::MacroDef(m) => result.macros.push(m),
                    TopLevelDef::PcodeOp(p) => result.pcode_macros.push(p),
                    TopLevelDef::ConstructorDef(c) => result.constructors.push(c),
                    TopLevelDef::SubConstructorDef(s) => result.subconstructors.push(s),
                    TopLevelDef::WithBlock(constructors) => {
                        result.constructors.extend(constructors)
                    }
                }
            }
            Ok((rest, None)) => {
                remaining = rest;
                // Nothing parsed, continue
            }
            Err(nom::Err::Error(_)) => {
                // Skip one character and try again (recovery)
                if let Some(c) = remaining.chars().next() {
                    if c == '\n' {
                        remaining = &remaining[1..];
                    } else {
                        // Skip the problematic line
                        let rest = remaining
                            .find('\n')
                            .map(|p| &remaining[p + 1..])
                            .unwrap_or("");
                        remaining = rest;
                    }
                } else {
                    break;
                }
            }
            Err(e) => return Err(e),
        }
    }

    Ok(result)
}

/// Parse a single constructor from a string.
///
/// This is the public entry point for parsing a standalone constructor line
/// (e.g. `:NOP is op=0xEA {}`).
pub fn parse_constructor(input: &str) -> IResult<&str, Constructor> {
    parse_constructor_inner(input)
}

/// Parse a single expression from a string.
///
/// Parses a P-code expression such as `A + 1`, `*:1 SP`, or `carry(A, B)`.
pub fn parse_expression(input: &str) -> IResult<&str, Expression> {
    parse_expression_inner(input)
}

/// Parse a single semantic statement from a string.
///
/// Parses one complete semantic statement including the trailing semicolon,
/// e.g. `A = A + 1;` or `if (Z == 0) goto L;`.
pub fn parse_semantic_statement(input: &str) -> IResult<&str, SemanticStatement> {
    parse_semantic_stmt_inner(input)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Helper parsers ---

    #[test]
    fn test_identifier() {
        assert_eq!(identifier("abc_def"), Ok(("", "abc_def".to_string())));
        assert_eq!(identifier("_abc123 "), Ok((" ", "_abc123".to_string())));
        assert!(identifier("123abc").is_err());
    }

    #[test]
    fn test_integer() {
        assert_eq!(integer("123"), Ok(("", 123)));
        assert_eq!(integer("0xff"), Ok(("", 255)));
        assert_eq!(integer("0xFF"), Ok(("", 255)));
        assert_eq!(integer("0b1010"), Ok(("", 10)));
        assert_eq!(integer("0B1010"), Ok(("", 10)));
    }

    #[test]
    fn test_quoted_mnemonic() {
        assert_eq!(quoted_mnemonic("\"NZ\""), Ok(("", "NZ".to_string())));
    }

    // --- Define statements ---

    #[test]
    fn test_parse_endian() {
        assert_eq!(
            parse_endian("define endian=little;"),
            Ok(("", Endian::Little))
        );
        assert_eq!(parse_endian("define endian=big;"), Ok(("", Endian::Big)));
    }

    #[test]
    fn test_parse_alignment() {
        assert_eq!(parse_alignment("define alignment=2;"), Ok(("", 2)));
        assert_eq!(parse_alignment("define alignment=1;"), Ok(("", 1)));
    }

    #[test]
    fn test_parse_space() {
        let (_, def) = parse_space("define space ram type=ram_space size=2 default;").unwrap();
        assert_eq!(def.name, "ram");
        assert_eq!(def.space_type, SpaceType::RamSpace);
        assert_eq!(def.size, 2);

        let (_, def) = parse_space("define space register type=register_space size=1;").unwrap();
        assert_eq!(def.name, "register");
        assert_eq!(def.space_type, SpaceType::RegisterSpace);
        assert_eq!(def.size, 1);
    }

    #[test]
    fn test_parse_register() {
        let (_, regs) = parse_register("define register offset=0x00 size=1 [ A X Y ];").unwrap();
        assert_eq!(regs.len(), 3);
        assert_eq!(regs[0].name, "A");
        assert_eq!(regs[0].offset, 0);
        assert_eq!(regs[0].size, 1);
    }

    #[test]
    fn test_parse_token() {
        let (_, tok) =
            parse_token("define token opbyte (8) op = (0,7) aaa = (5,7) signed ;").unwrap();
        assert_eq!(tok.name, "opbyte");
        assert_eq!(tok.size, 8);
        assert_eq!(tok.fields.len(), 2);
        assert_eq!(tok.fields[0].name, "op");
        assert_eq!(tok.fields[0].start, 0);
        assert_eq!(tok.fields[0].end, 7);
        assert!(!tok.fields[0].is_signed);
        assert_eq!(tok.fields[1].name, "aaa");
        assert!(tok.fields[1].is_signed);
    }

    #[test]
    fn test_parse_context() {
        let (_, fields) =
            parse_context("define context contextreg doublebyte = (0,0) noflow ;").unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "doublebyte");
        assert!(!fields[0].is_flow);
    }

    #[test]
    fn test_parse_pcodeop() {
        let (_, op) = parse_pcodeop("define pcodeop readIRQ;").unwrap();
        assert_eq!(op.name, "readIRQ");
    }

    #[test]
    fn test_parse_attach() {
        let (_, att) =
            parse_attach("attach variables [ reg0_3 reg3_3 ] [ B C D E L H _ A ];").unwrap();
        assert_eq!(att.name, "B");
        assert_eq!(att.registers.len(), 2);
    }

    // --- Macros ---

    #[test]
    fn test_parse_macro() {
        let (_, m) = parse_macro(
            "macro popSR() {
                SP = SP + 1;
                local ccr = *:1 SP;
            }",
        )
        .unwrap();
        assert_eq!(m.name, "popSR");
        assert!(m.parameters.is_empty());
        assert_eq!(m.body.len(), 2);
    }

    // --- Pattern expressions ---

    #[test]
    fn test_pattern_simple() {
        let (_, pat) = parse_pattern_expression("op=0x90").unwrap();
        match pat {
            PatternExpr::FieldValue { field, value } => {
                assert_eq!(field, "op");
                match value {
                    PatternValue::Constant(0x90) => {}
                    _ => panic!("Expected constant 0x90"),
                }
            }
            _ => panic!("Expected FieldValue"),
        }
    }

    #[test]
    fn test_pattern_and() {
        let (_, pat) = parse_pattern_expression("cc=1 & aaa=3").unwrap();
        match pat {
            PatternExpr::And(left, right) => {
                match *left {
                    PatternExpr::FieldValue { field, .. } => assert_eq!(field, "cc"),
                    _ => panic!("Expected FieldValue for cc"),
                }
                match *right {
                    PatternExpr::FieldValue { field, .. } => assert_eq!(field, "aaa"),
                    _ => panic!("Expected FieldValue for aaa"),
                }
            }
            _ => panic!("Expected And"),
        }
    }

    #[test]
    fn test_pattern_or() {
        let (_, pat) = parse_pattern_expression("op=0x06 | op=0x0A | op=0x0E").unwrap();
        match pat {
            PatternExpr::Or(_, _) => {}
            _ => panic!("Expected Or"),
        }
    }

    #[test]
    fn test_pattern_table_ref() {
        let (_, pat) = parse_pattern_expression("OP1").unwrap();
        match pat {
            PatternExpr::TableRef(name) => assert_eq!(name, "OP1"),
            _ => panic!("Expected TableRef"),
        }
    }

    #[test]
    fn test_pattern_ellipsis() {
        let (_, pat) = parse_pattern_expression("op=0x90 ... & REL").unwrap();
        // Should parse as: (op=0x90) AND (ELLIPSIS AND REL)
        match pat {
            PatternExpr::And(left, _) => match *left {
                PatternExpr::FieldValue { field, .. } => assert_eq!(field, "op"),
                _ => panic!("Expected FieldValue for op"),
            },
            _ => panic!("Expected And"),
        }
    }

    // --- Expressions ---

    #[test]
    fn test_expression_identifier() {
        let (_, expr) = parse_expression_inner("A").unwrap();
        match expr {
            Expression::Identifier(name) => assert_eq!(name, "A"),
            _ => panic!("Expected Identifier"),
        }
    }

    #[test]
    fn test_expression_number() {
        let (_, expr) = parse_expression_inner("42").unwrap();
        match expr {
            Expression::Number(42) => {}
            _ => panic!("Expected Number 42"),
        }
    }

    #[test]
    fn test_expression_binary() {
        let (_, expr) = parse_expression_inner("A + 1").unwrap();
        match expr {
            Expression::BinaryOp { op, left, right } => {
                assert_eq!(op, BinaryOperator::Add);
                match *left {
                    Expression::Identifier(name) => assert_eq!(name, "A"),
                    _ => panic!("Expected Identifier A"),
                }
                match *right {
                    Expression::Number(1) => {}
                    _ => panic!("Expected Number 1"),
                }
            }
            _ => panic!("Expected BinaryOp"),
        }
    }

    #[test]
    fn test_expression_comparison() {
        let (_, expr) = parse_expression_inner("Z == 0").unwrap();
        match expr {
            Expression::BinaryOp { op, .. } => assert_eq!(op, BinaryOperator::Equal),
            _ => panic!("Expected BinaryOp"),
        }
    }

    #[test]
    fn test_expression_signed_compare() {
        let (_, expr) = parse_expression_inner("result s< 0").unwrap();
        match expr {
            Expression::BinaryOp { op, .. } => assert_eq!(op, BinaryOperator::SLess),
            _ => panic!("Expected BinaryOp s<"),
        }
    }

    #[test]
    fn test_expression_varnode() {
        let (_, expr) = parse_expression_inner("*:1 SP").unwrap();
        match expr {
            Expression::Varnode(vn) => {
                assert_eq!(vn.size, 1);
                assert!(vn.space.is_none());
            }
            _ => panic!("Expected Varnode"),
        }
    }

    #[test]
    fn test_expression_varnode_with_space() {
        let (_, expr) = parse_expression_inner("*[io]:1 imm8").unwrap();
        match expr {
            Expression::Varnode(vn) => {
                assert_eq!(vn.size, 1);
                assert_eq!(vn.space, Some("io".to_string()));
            }
            _ => panic!("Expected Varnode with space"),
        }
    }

    #[test]
    fn test_expression_field_extract() {
        let (_, expr) = parse_expression_inner("ccr[7,1]").unwrap();
        match expr {
            Expression::FieldExtract { value, start, end } => {
                match *value {
                    Expression::Identifier(name) => assert_eq!(name, "ccr"),
                    _ => panic!("Expected Identifier ccr"),
                }
                match *start {
                    Expression::Number(7) => {}
                    _ => panic!("Expected Number 7"),
                }
                match *end {
                    Expression::Number(1) => {}
                    _ => panic!("Expected Number 1"),
                }
            }
            _ => panic!("Expected FieldExtract"),
        }
    }

    #[test]
    fn test_expression_function_call() {
        let (_, expr) = parse_expression_inner("carry(A, 1)").unwrap();
        match expr {
            Expression::FunctionCall { name, args } => {
                assert_eq!(name, "carry");
                assert_eq!(args.len(), 2);
            }
            _ => panic!("Expected FunctionCall"),
        }
    }

    #[test]
    fn test_expression_complex() {
        // Test: ((register & ~operand & ~result) | (...)) != 0
        let (_, expr) = parse_expression_inner("(A & ~operand & ~result) != 0").unwrap();
        match expr {
            Expression::BinaryOp { op, .. } => assert_eq!(op, BinaryOperator::NotEqual),
            _ => panic!("Expected BinaryOp !="),
        }
    }

    #[test]
    fn test_expression_precedence() {
        // a + b * c should parse as a + (b * c)
        let (_, expr) = parse_expression_inner("A + B * 2").unwrap();
        match expr {
            Expression::BinaryOp { op, left: _, right } => {
                assert_eq!(op, BinaryOperator::Add);
                // right should be B * 2
                match *right {
                    Expression::BinaryOp { op, .. } => assert_eq!(op, BinaryOperator::Mul),
                    _ => panic!("Expected Mul on right"),
                }
            }
            _ => panic!("Expected BinaryOp"),
        }
    }

    // --- Semantic statements ---

    #[test]
    fn test_semantic_assign() {
        let (_, stmt) = parse_semantic_stmt_inner("A = A + 1;").unwrap();
        match stmt {
            SemanticStatement::Assign { .. } => {}
            _ => panic!("Expected Assign"),
        }
    }

    #[test]
    fn test_semantic_local() {
        let (_, stmt) = parse_semantic_stmt_inner("local tmp:1 = 0;").unwrap();
        match stmt {
            SemanticStatement::LocalVar { name, size, init } => {
                assert_eq!(name, "tmp");
                assert_eq!(size, 1);
                assert!(init.is_some());
            }
            _ => panic!("Expected LocalVar"),
        }
    }

    #[test]
    fn test_semantic_export() {
        let (_, stmt) = parse_semantic_stmt_inner("export *:2 reloc;").unwrap();
        match stmt {
            SemanticStatement::Export { size, .. } => {
                assert_eq!(size, 2);
            }
            _ => panic!("Expected Export"),
        }
    }

    #[test]
    fn test_semantic_build() {
        let (_, stmt) = parse_semantic_stmt_inner("build checkbranch;").unwrap();
        match stmt {
            SemanticStatement::Build { name } => assert_eq!(name, "checkbranch"),
            _ => panic!("Expected Build"),
        }
    }

    #[test]
    fn test_semantic_if_goto() {
        let (_, stmt) = parse_semantic_stmt_inner("if (C == 0) goto REL;").unwrap();
        match stmt {
            SemanticStatement::IfGoto { .. } => {}
            _ => panic!("Expected IfGoto"),
        }
    }

    #[test]
    fn test_semantic_goto() {
        let (_, stmt) = parse_semantic_stmt_inner("goto inst_start;").unwrap();
        match stmt {
            SemanticStatement::Goto { .. } => {}
            _ => panic!("Expected Goto"),
        }
    }

    #[test]
    fn test_semantic_call() {
        let (_, stmt) = parse_semantic_stmt_inner("call ADDR16;").unwrap();
        match stmt {
            SemanticStatement::Call { .. } => {}
            _ => panic!("Expected Call"),
        }
    }

    #[test]
    fn test_semantic_store() {
        let (_, stmt) = parse_semantic_stmt_inner("*:1 ptr = A;").unwrap();
        match stmt {
            SemanticStatement::Store { .. } => {}
            _ => panic!("Expected Store"),
        }
    }

    #[test]
    fn test_semantic_macro_call() {
        let (_, stmt) = parse_semantic_stmt_inner("popSR();").unwrap();
        match stmt {
            SemanticStatement::MacroCall { name, .. } => assert_eq!(name, "popSR"),
            _ => panic!("Expected MacroCall"),
        }
    }

    // --- Constructors ---

    #[test]
    fn test_parse_constructor_simple() {
        let input = ":NOP is op=0xEA {}";
        let (_, c) = parse_constructor_inner(input).unwrap();
        assert_eq!(c.header.mnemonic, "NOP");
        assert!(c.table_name.is_none());
        assert!(c.semantics.is_empty());
    }

    #[test]
    fn test_parse_constructor_with_operands() {
        let input = ":ADC OP1 is (cc=1 & aaa=3) ... & OP1 { A = OP1; }";
        let (_, c) = parse_constructor_inner(input).unwrap();
        assert_eq!(c.header.mnemonic, "ADC");
        assert_eq!(c.header.operand_patterns.len(), 1);
        assert_eq!(c.header.operand_patterns[0].name, "OP1");
        assert_eq!(c.semantics.len(), 1);
    }

    #[test]
    fn test_parse_subconstructor() {
        let input = "REL: reloc is rel [ reloc = inst_next + rel; ]";
        let (_, sc) = parse_subconstructor(input).unwrap();
        assert_eq!(sc.table_name, Some("REL".to_string()));
        assert_eq!(sc.header.mnemonic, "reloc");
    }

    #[test]
    fn test_parse_6502_full() {
        let input = r#"
define endian=little;
define alignment=1;

define space ram type=ram_space size=2 default;
define space register type=register_space size=1;

define register offset=0x00 size=1 [ A X Y ];
define register offset=0x20 size=2 [ PC SP ];

define token opbyte (8)
   op = (0,7)
   aaa = (5,7)
;

:NOP is op=0xEA {}
:CLC is op=0x18 { C = 0; }
        "#;
        let result = parse_slaspec(input).unwrap();
        assert_eq!(result.endian, Endian::Little);
        assert_eq!(result.alignment, 1);
        assert_eq!(result.spaces.len(), 2);
        assert_eq!(result.registers.len(), 5);
        assert_eq!(result.tokens.len(), 1);
        assert_eq!(result.constructors.len(), 2);
    }

    #[test]
    fn test_parse_with_block() {
        let input = r#"
with : operation_size=1 {
    :RLC reg0_2, 2 is opcode3_9=0x000A & reg0_2 { reg0_2 = regval0_2 << 2; }
    :RRC reg0_2, 2 is opcode3_9=0x000E & reg0_2 { reg0_2 = regval0_2 >> 2; }
}
        "#;
        let (_, constructors) = parse_with_block(input).unwrap();
        assert_eq!(constructors.len(), 2);
        // Each constructor's pattern should be ANDed with the context
        match &constructors[0].pattern {
            PatternExpr::And(ctx, _) => match &**ctx {
                PatternExpr::FieldValue { field, .. } => assert_eq!(field, "operation_size"),
                _ => panic!("Expected context field"),
            },
            _ => panic!("Expected And"),
        }
    }

    #[test]
    fn test_parse_macro_full() {
        let input = r#"
macro push16(val16) {
    SP = SP - 2;
    *:2 SP = val16;
}
        "#;
        let (_, m) = parse_macro(input).unwrap();
        assert_eq!(m.name, "push16");
        assert_eq!(m.parameters, vec!["val16"]);
        assert_eq!(m.body.len(), 2);
    }
}
