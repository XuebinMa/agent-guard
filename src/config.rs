#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuntimePermissionRuleConfig {
    allow: Vec<String>,
    deny: Vec<String>,
    ask: Vec<String>,
}

impl RuntimePermissionRuleConfig {
    pub fn new(allow: Vec<String>, deny: Vec<String>, ask: Vec<String>) -> Self {
        Self { allow, deny, ask }
    }
    pub fn allow(&self) -> &[String] { &self.allow }
    pub fn deny(&self) -> &[String] { &self.deny }
    pub fn ask(&self) -> &[String] { &self.ask }
}
