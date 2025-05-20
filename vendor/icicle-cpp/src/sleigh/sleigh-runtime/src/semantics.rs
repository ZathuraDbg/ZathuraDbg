pub type ValueSize = u16;

#[derive(Debug, Clone)]
pub enum SemanticAction {
    Op { op: pcode::Op, inputs: Vec<Value>, output: Option<Value> },
    AddressOf { output: Value, base: Local },
    LoadRegister { pointer: Value, output: Value, size: ValueSize },
    StoreRegister { pointer: Value, value: Value, size: ValueSize },
    DelaySlot,
    Build(u32),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Value {
    /// The underlying local variable that the value is derived from.
    pub local: Local,

    /// The byte offset of the value from the start of the local.
    pub offset: ValueSize,

    /// The size of the value in bytes.
    pub size: Option<ValueSize>,
}

impl Value {
    pub fn constant(value: u64) -> Self {
        Self { local: Local::Constant(value), offset: 0, size: None }
    }

    pub fn truncate(self, size: ValueSize) -> Self {
        Self { size: Some(size), ..self }
    }

    pub fn maybe_set_size(self, size: Option<ValueSize>) -> Self {
        Self { size: size.or(self.size), ..self }
    }

    pub fn slice_bytes(mut self, offset: ValueSize, size: ValueSize) -> Self {
        self.offset += offset;
        self.truncate(size)
    }
}

impl From<Local> for Value {
    fn from(local: Local) -> Self {
        Self { local, offset: 0, size: None }
    }
}

/// Encodes the value exported by the constructor.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Export {
    /// A statically computed value.
    Value(Value),

    /// A pointer to an address in the RAM space.
    RamRef(Value, ValueSize),

    /// A dynamically computed register.
    RegisterRef(Value, ValueSize),
}

impl Export {
    pub fn size(&self) -> Option<ValueSize> {
        match self {
            Self::Value(inner) => inner.size,
            Self::RamRef(_, size) => Some(*size),
            Self::RegisterRef(_, size) => Some(*size),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PcodeTmp {
    pub name: Option<sleigh_parse::ast::Ident>,
    pub size: Option<ValueSize>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Local {
    /// The address of the current instruction.
    InstStart,

    /// The address of the next instruction.
    InstNext,

    /// A reference to a register
    Register(u32),

    /// A field declared in either the constraint expression or disassembly actions section
    Field(u32),

    /// A reference to the exported value of a subtable. On use this value is automatically
    /// dereferenced.
    ///
    /// Note: this represents the offset into `constructor.subtables` not the TableId.
    Subtable(u32),

    /// A reference to the export of a subtable that is not automatically dereferenced on use.
    SubtableRef(u32),

    /// Represents a temporary inside of the semantics section
    PcodeTmp(u32),

    /// Represents a constant inside of the semantics section
    Constant(u64),
}
