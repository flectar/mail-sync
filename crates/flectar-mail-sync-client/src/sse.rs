//! Server-Sent Events, as the WHATWG HTML standard defines the stream
//! format: lines end in CR, LF or CRLF; `event` and `data` fields build an
//! event, and a blank line dispatches it; lines starting with a colon are
//! comments.

use flectar_mail_sync_proto::{ChainEvent, SeqEvent};

/// What the server announced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// The group's newest record sequence number.
    Seq(u64),
    /// The index of the chain's newest operation.
    Chain(u64),
}

/// Incremental parser: feed it chunks as they arrive.
#[derive(Debug, Default)]
pub struct SseParser {
    line: Vec<u8>,
    /// The previous chunk ended in CR, so a leading LF ends no line.
    after_cr: bool,
    event: String,
    data: String,
    started: bool,
}

impl SseParser {
    pub fn push(&mut self, chunk: &[u8]) -> Vec<Event> {
        let mut events = Vec::new();
        for &byte in chunk {
            match byte {
                b'\n' if self.after_cr => self.after_cr = false,
                b'\n' | b'\r' => {
                    self.after_cr = byte == b'\r';
                    let line = std::mem::take(&mut self.line);
                    if let Some(event) = self.line_done(&line) {
                        events.push(event);
                    }
                }
                _ => {
                    self.after_cr = false;
                    self.line.push(byte);
                }
            }
        }
        events
    }

    fn line_done(&mut self, line: &[u8]) -> Option<Event> {
        let mut line = String::from_utf8_lossy(line).into_owned();
        if !self.started {
            self.started = true;
            if let Some(rest) = line.strip_prefix('\u{feff}') {
                line = rest.to_owned();
            }
        }
        if line.is_empty() {
            return self.dispatch();
        }
        if line.starts_with(':') {
            return None;
        }
        let (field, value) = match line.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (line.as_str(), ""),
        };
        match field {
            "event" => self.event = value.to_owned(),
            "data" => {
                self.data.push_str(value);
                self.data.push('\n');
            }
            _ => {}
        }
        None
    }

    fn dispatch(&mut self) -> Option<Event> {
        let event = std::mem::take(&mut self.event);
        let mut data = std::mem::take(&mut self.data);
        if data.is_empty() {
            return None;
        }
        data.pop();
        match event.as_str() {
            "seq" => serde_json::from_str::<SeqEvent>(&data)
                .ok()
                .map(|event| Event::Seq(event.high_seq)),
            "chain" => serde_json::from_str::<ChainEvent>(&data)
                .ok()
                .map(|event| Event::Chain(event.head_index)),
            // Event types from newer servers.
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_survive_any_chunking_and_line_ending() {
        let stream = "\u{feff}: keep-alive\r\nevent: seq\r\ndata: {\"highSeq\":12}\r\n\r\n\
                      event: chain\rdata: {\"headIndex\":3}\r\r\
                      event: future\ndata: {}\n\n\
                      event: seq\ndata: {\"highSeq\":13}\n\n";
        let expected = vec![Event::Seq(12), Event::Chain(3), Event::Seq(13)];
        for size in 1..stream.len() {
            let mut parser = SseParser::default();
            let events: Vec<Event> = stream
                .as_bytes()
                .chunks(size)
                .flat_map(|chunk| parser.push(chunk))
                .collect();
            assert_eq!(events, expected, "chunks of {size}");
        }
    }

    #[test]
    fn data_lines_join_and_malformed_events_are_skipped() {
        let mut parser = SseParser::default();
        assert_eq!(
            parser.push(b"event: seq\ndata: {\"highSeq\":\ndata: 5}\n\nevent: seq\ndata: nope\n\n"),
            vec![Event::Seq(5)]
        );
    }
}
