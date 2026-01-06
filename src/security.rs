use swiftsc_frontend::ast::*;

#[derive(Debug, Clone)]
pub enum SecurityWarning {
    PotentialOverflow { operation: String, span: Span },
    UninitializedVariable { name: String, span: Span },
    UncheckedArithmetic { operation: String, span: Span },
    PotentialReentrancy { message: String, span: Span },
}

impl SecurityWarning {
    pub fn code(&self) -> &'static str {
        match self {
            SecurityWarning::PotentialOverflow { .. } => "SEC-003",
            SecurityWarning::UninitializedVariable { .. } => "SEC-004",
            SecurityWarning::UncheckedArithmetic { .. } => "SEC-003",
            SecurityWarning::PotentialReentrancy { .. } => "SEC-002",
        }
    }

    pub fn message(&self) -> String {
        match self {
            SecurityWarning::PotentialOverflow { operation, .. } => {
                format!("[{}] Potential Overflow in operation: {}", self.code(), operation)
            }
            SecurityWarning::UninitializedVariable { name, .. } => {
                format!("[{}] Uninitialized storage variable: {}", self.code(), name)
            }
            SecurityWarning::UncheckedArithmetic { operation, .. } => {
                format!("[{}] Unchecked arithmetic operation: {}. Consider using SafeMath.", self.code(), operation)
            }
            SecurityWarning::PotentialReentrancy { message, .. } => {
                format!("[{}] Potential Reentrancy: {}", self.code(), message)
            }
        }
    }
}

pub struct SecurityAnalyzer {
    warnings: Vec<SecurityWarning>,
    external_call_seen: bool,
    current_function: Option<String>,
}

impl Default for SecurityAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityAnalyzer {
    pub fn new() -> Self {
        SecurityAnalyzer {
            warnings: Vec::new(),
            external_call_seen: false,
            current_function: None,
        }
    }

    pub fn analyze_program(&mut self, program: &Program) {
        for item in &program.items {
            match item {
                Item::Contract(contract) => self.analyze_contract(contract),
                Item::Function(func) => self.analyze_function(func),
                _ => {}
            }
        }
    }

    fn analyze_contract(&mut self, contract: &Contract) {
        let mut storage_fields = std::collections::HashSet::new();
        for member in &contract.members {
            if let ContractMember::Storage(fields) = member {
                for field in fields {
                    storage_fields.insert(field.name.clone());
                }
            }
        }

        for member in &contract.members {
            if let ContractMember::Init(func) = member {
                let mut initialized = std::collections::HashSet::new();
                self.collect_initializations(&func.body, &mut initialized);

                for field in &storage_fields {
                    if !initialized.contains(field) {
                        // For constructor, span is the function body or the field itself if we had it.
                        // Using func's body span for now.
                        self.warnings.push(SecurityWarning::UninitializedVariable {
                            name: format!("Storage field '{}'", field),
                            span: func.body.stmts.first().map(|s| s.span).unwrap_or(Span::new(1, 1)),
                        });
                    }
                }
            } else if let ContractMember::Function(func) = member {
                self.analyze_function(func);
            }
        }
    }

    fn collect_initializations(
        &self,
        block: &Block,
        initialized: &mut std::collections::HashSet<String>,
    ) {
        for stmt in &block.stmts {
            if let StatementKind::Expr(expr) = &stmt.kind {
                if let ExpressionKind::Binary { left, op, .. } = &expr.kind {
                    if *op == BinaryOp::Assign {
                        if let ExpressionKind::FieldAccess { expr: obj, field } = &left.kind {
                            if let ExpressionKind::Identifier(name) = &obj.kind {
                                if name == "self" {
                                    initialized.insert(field.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn analyze_function(&mut self, func: &Function) {
        self.external_call_seen = false;
        self.current_function = Some(func.name.clone());
        self.analyze_block(&func.body);
        self.current_function = None;
    }

    fn analyze_block(&mut self, block: &Block) {
        for stmt in &block.stmts {
            self.analyze_statement(stmt);
        }
    }

    fn analyze_statement(&mut self, stmt: &Statement) {
        match &stmt.kind {
            StatementKind::Let { init, .. } => {
                self.analyze_expression(init);
            }
            StatementKind::Expr(expr) => {
                self.analyze_expression(expr);
            }
            StatementKind::Return(Some(expr)) => {
                self.analyze_expression(expr);
            }
            StatementKind::If {
                condition,
                then_branch,
                else_branch,
            } => {
                self.analyze_expression(condition);
                self.analyze_block(then_branch);
                if let Some(eb) = else_branch {
                    self.analyze_block(eb);
                }
            }
            StatementKind::While { condition, body } => {
                self.analyze_expression(condition);
                self.analyze_block(body);
            }
            StatementKind::For { start, end, body, .. } => {
                self.analyze_expression(start);
                self.analyze_expression(end);
                self.analyze_block(body);
            }
            _ => {}
        }
    }

    fn analyze_expression(&mut self, expr: &Expression) {
        match &expr.kind {
            ExpressionKind::Binary { left, op, right } => {
                if *op == BinaryOp::Assign && self.external_call_seen {
                    if let ExpressionKind::FieldAccess { expr: obj, .. } = &left.kind {
                        if let ExpressionKind::Identifier(name) = &obj.kind {
                            if name == "self" {
                                self.warnings.push(SecurityWarning::PotentialReentrancy {
                                    message: "Detected state modification after potential external call".to_string(),
                                    span: expr.span,
                                });
                            }
                        }
                    }
                }

                match op {
                    BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul => {
                        let is_safe_context = self.current_function.as_ref().map_or(false, |name| {
                            name.starts_with("checked_") || name.starts_with("safe_")
                        });

                        if !is_safe_context {
                            self.warnings.push(SecurityWarning::UncheckedArithmetic {
                                operation: format!("{:?}", op),
                                span: expr.span,
                            });
                        }
                    }
                    _ => {}
                }
                self.analyze_expression(left);
                self.analyze_expression(right);
            }
            ExpressionKind::Call { func, args, .. } => {
                if let ExpressionKind::FieldAccess { expr: obj, .. } = &func.kind {
                    if let ExpressionKind::Identifier(name) = &obj.kind {
                        if name != "self" {
                            self.external_call_seen = true;
                        }
                    }
                }

                self.analyze_expression(func);
                for arg in args {
                    self.analyze_expression(arg);
                }
            }
            ExpressionKind::FieldAccess { expr: obj, .. } => {
                self.analyze_expression(obj);
            }
            ExpressionKind::Index { expr: obj, index } => {
                self.analyze_expression(obj);
                self.analyze_expression(index);
            }
            ExpressionKind::Match { value, arms } => {
                self.analyze_expression(value);
                for arm in arms {
                    self.analyze_expression(&arm.body);
                }
            }
            ExpressionKind::StructInit { fields, .. } => {
                for (_, f_expr) in fields {
                    self.analyze_expression(f_expr);
                }
            }
            ExpressionKind::Try(e) => {
                self.analyze_expression(e);
            }
            ExpressionKind::GenericInst { target, .. } => {
                self.analyze_expression(target);
            }
            _ => {}
        }
    }

    pub fn get_warnings(&self) -> &[SecurityWarning] {
        &self.warnings
    }

    pub fn has_critical_warnings(&self) -> bool {
        false
    }
}
