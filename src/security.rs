use swiftsc_frontend::ast::*;

#[derive(Debug, Clone)]
pub enum SecurityWarning {
    PotentialOverflow { operation: String, location: String },
    UninitializedVariable { name: String },
    UncheckedArithmetic { operation: String },
    PotentialReentrancy { location: String },
}

pub struct SecurityAnalyzer {
    warnings: Vec<SecurityWarning>,
    external_call_seen: bool,
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
        }
    }

    pub fn analyze_program(&mut self, program: &Program) {
        for item in &program.items {
            match item {
                Item::Contract(contract) => self.analyze_contract(contract),
                Item::Function(func) => self.analyze_function(func),
                _ => {} // Ignore Use, Struct, Enum, etc. for now
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
                // Check if all storage fields are initialized in the constructor
                let mut initialized = std::collections::HashSet::new();
                self.collect_initializations(&func.body, &mut initialized);

                for field in &storage_fields {
                    if !initialized.contains(field) {
                        self.warnings.push(SecurityWarning::UninitializedVariable {
                            name: format!("Storage field '{}'", field),
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
            if let Statement::Expr(Expression::Binary { left, op, .. }) = stmt {
                if *op == BinaryOp::Assign {
                    if let Expression::FieldAccess { expr: obj, field } = &**left {
                        if let Expression::Identifier(name) = &**obj {
                            if name == "self" {
                                initialized.insert(field.clone());
                            }
                        }
                    }
                }
            }
            // Recursive check for nested blocks (if/while) could be added here
        }
    }

    fn analyze_function(&mut self, func: &Function) {
        self.external_call_seen = false;
        self.analyze_block(&func.body);
    }

    fn analyze_block(&mut self, block: &Block) {
        for stmt in &block.stmts {
            self.analyze_statement(stmt);
        }
    }

    fn analyze_statement(&mut self, stmt: &Statement) {
        match stmt {
            Statement::Let { init, .. } => {
                self.analyze_expression(init);
            }
            Statement::Expr(expr) => {
                self.analyze_expression(expr);
            }
            Statement::Return(Some(expr)) => {
                self.analyze_expression(expr);
            }
            Statement::If {
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
            _ => {}
        }
    }

    fn analyze_expression(&mut self, expr: &Expression) {
        match expr {
            Expression::Binary { left, op, right } => {
                if *op == BinaryOp::Assign && self.external_call_seen {
                    if let Expression::FieldAccess { expr: obj, .. } = &**left {
                        if let Expression::Identifier(name) = &**obj {
                            if name == "self" {
                                self.warnings.push(SecurityWarning::PotentialReentrancy {
                                    location:
                                        "Detected state modification after potential external call"
                                            .to_string(),
                                });
                            }
                        }
                    }
                }

                // Check for potential integer overflow in arithmetic
                match op {
                    BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul => {
                        self.warnings.push(SecurityWarning::UncheckedArithmetic {
                            operation: format!("{:?}", op),
                        });
                    }
                    _ => {}
                }
                self.analyze_expression(left);
                self.analyze_expression(right);
            }
            Expression::Call { func, args, .. } => {
                // Detection of potential external calls
                if let Expression::FieldAccess { expr: obj, .. } = &**func {
                    if let Expression::Identifier(name) = &**obj {
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
            Expression::FieldAccess { expr, .. } => {
                self.analyze_expression(expr);
            }
            _ => {}
        }
    }

    pub fn get_warnings(&self) -> &[SecurityWarning] {
        &self.warnings
    }

    pub fn has_critical_warnings(&self) -> bool {
        // For MVP, we don't have critical warnings yet
        false
    }
}
