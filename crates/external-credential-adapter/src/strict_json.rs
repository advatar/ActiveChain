//! Parse signed JSON without allowing duplicate member names to be collapsed.
use crate::SdJwtRejection;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;

pub(crate) fn parse(bytes: &[u8]) -> Result<Value, SdJwtRejection> {
    let mut parser = serde_json::Deserializer::from_slice(bytes);
    let mut rejection = SdJwtRejection::MalformedJson;
    let result = Seed { depth: 1, rejection: &mut rejection }.deserialize(&mut parser);
    let value = result.map_err(|_| rejection)?;
    parser.end().map_err(|_| SdJwtRejection::MalformedJson)?;
    Ok(value)
}

struct Seed<'a> {
    depth: usize,
    rejection: &'a mut SdJwtRejection,
}

impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        if self.depth > crate::MAX_JSON_DEPTH {
            *self.rejection = SdJwtRejection::Oversize;
            return Err(de::Error::custom("JSON depth limit"));
        }
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unambiguous bounded JSON")
    }
    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        Number::from_f64(value).map(Value::Number).ok_or_else(|| E::custom("invalid number"))
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) =
            sequence.next_element_seed(Seed { depth: self.depth + 1, rejection: self.rejection })?
        {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                *self.rejection = SdJwtRejection::DuplicateJsonKey;
                return Err(de::Error::custom("duplicate JSON member"));
            }
            let value = object
                .next_value_seed(Seed { depth: self.depth + 1, rejection: self.rejection })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_escaped_and_nested_duplicates() {
        for input in [
            r#" {"iss":"a","\u0069ss":"b"}"#,
            r#"{"cnf":{"jwk":{"x":"a","x":"b"}}}"#,
            r#"["salt","claim",{"x":1,"x":2}]"#,
        ] {
            assert_eq!(parse(input.as_bytes()), Err(SdJwtRejection::DuplicateJsonKey));
        }
    }

    #[test]
    fn permits_names_in_distinct_objects_and_punctuation_in_strings() {
        let input = br#"{"issuer":{"x":1},"holder":{"x":2},"label":"a,b:c"}"#;
        assert_eq!(parse(input).unwrap(), serde_json::from_slice::<Value>(input).unwrap());
    }

    #[test]
    fn rejects_trailing_data_and_excessive_depth() {
        assert_eq!(parse(b"{} {}"), Err(SdJwtRejection::MalformedJson));
        let nested = format!("{}0{}", "[".repeat(16), "]".repeat(16));
        assert_eq!(parse(nested.as_bytes()), Err(SdJwtRejection::Oversize));
    }
}
