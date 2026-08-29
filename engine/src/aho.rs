use std::collections::VecDeque;

#[derive(Debug)]
struct Node {
    next: [i32; 256],
    fail: usize,
    outputs: Vec<usize>,
}

impl Default for Node {
    fn default() -> Self {
        Self {
            next: [-1; 256],
            fail: 0,
            outputs: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct AhoCorasick {
    nodes: Vec<Node>,
}

impl Default for AhoCorasick {
    fn default() -> Self {
        Self {
            nodes: vec![Node::default()],
        }
    }
}

impl AhoCorasick {
    pub fn add(&mut self, bytes: &[u8], pattern_id: usize) {
        let mut curr = 0;

        for &byte in bytes {
            let next = self.nodes[curr].next[byte as usize];
            if next == -1 {
                let new_node = self.nodes.len();
                self.nodes.push(Node::default());

                self.nodes[curr].next[byte as usize] = new_node as i32;
                curr = new_node;
            } else {
                curr = next as usize;
            }
        }

        self.nodes[curr].outputs.push(pattern_id);
    }

    pub fn print(&self) {
        for (i, node) in self.nodes.iter().enumerate() {
            println!("Node {i}:");

            for (byte, &child) in node.next.iter().enumerate() {
                if child != -1 {
                    println!("  '{}' ({byte}) -> Node {child}", byte as u8 as char);
                }
            }

            println!("  outputs: {:?}", node.outputs);
        }
    }

    pub fn create_failure_links(&mut self) {
        let mut queue = VecDeque::new();
        for i in 0..256 {
            let child = self.nodes[0].next[i];
            if child != -1 {
                self.nodes[child as usize].fail = 0;
                queue.push_back(child);
            }
        }

        while let Some(curr) = queue.pop_front() {
            for byte in 0..256 {
                let child = self.nodes[curr as usize].next[byte];
                if child == -1 {
                    continue;
                }

                let mut fail = self.nodes[curr as usize].fail;
                while fail != 0 && self.nodes[fail].next[byte] == -1 {
                    fail = self.nodes[fail].fail;
                }

                if self.nodes[fail].next[byte] != -1 {
                    fail = self.nodes[fail].next[byte] as usize;
                } else {
                    fail = 0;
                }

                self.nodes[child as usize].fail = fail;

                //merges outputs from failutes
                let fail_outputs = self.nodes[fail].outputs.clone();
                self.nodes[child as usize].outputs.extend(fail_outputs);

                queue.push_back(child);
            }
        }
    }

    pub fn search(&self, pattern: &[u8]) -> Vec<usize> {
        let mut curr: usize = 0;
        let mut patterns = Vec::new();
        for &bytes in pattern {
            let bytes = bytes as usize;
            while curr != 0 && self.nodes[curr].next[bytes] == -1 {
                curr = self.nodes[curr].fail;
            }

            if self.nodes[curr].next[bytes] != -1 {
                curr = self.nodes[curr].next[bytes] as usize;
            } else {
                curr = 0;
            }

            patterns.extend(self.nodes[curr].outputs.iter().copied());
        }

        patterns
    }
}
