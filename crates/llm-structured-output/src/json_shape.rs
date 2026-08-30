use omnius_llm_core::{JsonObject, SchemaDefinition};
use omnius_validation::{JsonStructureError, JsonValidationLimits};
use serde_json::Value;

pub(crate) fn validate_schema_shape(
    schema: &SchemaDefinition,
    limits: JsonValidationLimits,
) -> Result<(), JsonStructureError> {
    match schema {
        SchemaDefinition::Boolean(_) => Ok(()),
        SchemaDefinition::Object(object) => validate_nodes(ShapeNode::Object(object), limits),
    }
}

pub(crate) fn validate_value_shape(
    value: &Value,
    limits: JsonValidationLimits,
) -> Result<(), JsonStructureError> {
    validate_nodes(ShapeNode::Value(value), limits)
}

enum ShapeNode<'a> {
    Value(&'a Value),
    Object(&'a JsonObject),
}

fn validate_nodes(
    root: ShapeNode<'_>,
    limits: JsonValidationLimits,
) -> Result<(), JsonStructureError> {
    let mut stack = vec![(root, 0_usize)];
    let mut nodes = 0_usize;
    while let Some((node, depth)) = stack.pop() {
        if depth > limits.max_depth {
            return Err(JsonStructureError::TooDeep);
        }
        nodes = nodes.saturating_add(1);
        if nodes > limits.max_nodes {
            return Err(JsonStructureError::TooManyNodes);
        }
        match node {
            ShapeNode::Value(Value::String(value)) if value.len() > limits.max_string_bytes => {
                return Err(JsonStructureError::StringTooLong);
            }
            ShapeNode::Value(Value::Array(values)) => {
                if values.len() > limits.max_array_items {
                    return Err(JsonStructureError::ArrayTooLong);
                }
                admit_children(values.len(), nodes, stack.len(), limits.max_nodes)?;
                stack.extend(
                    values
                        .iter()
                        .map(|child| (ShapeNode::Value(child), depth.saturating_add(1))),
                );
            }
            ShapeNode::Value(Value::Object(values)) => {
                admit_object(
                    values.len(),
                    values.iter(),
                    nodes,
                    stack.len(),
                    depth,
                    limits,
                    &mut stack,
                )?;
            }
            ShapeNode::Object(values) => {
                admit_object(
                    values.len(),
                    values.iter(),
                    nodes,
                    stack.len(),
                    depth,
                    limits,
                    &mut stack,
                )?;
            }
            ShapeNode::Value(
                Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_),
            ) => {}
        }
    }
    Ok(())
}

fn admit_object<'a, I>(
    property_count: usize,
    values: I,
    nodes: usize,
    retained_nodes: usize,
    depth: usize,
    limits: JsonValidationLimits,
    stack: &mut Vec<(ShapeNode<'a>, usize)>,
) -> Result<(), JsonStructureError>
where
    I: IntoIterator<Item = (&'a String, &'a Value)>,
{
    if property_count > limits.max_object_properties {
        return Err(JsonStructureError::ObjectTooLarge);
    }
    admit_children(property_count, nodes, retained_nodes, limits.max_nodes)?;
    for (property, child) in values {
        if property.len() > limits.max_string_bytes {
            return Err(JsonStructureError::StringTooLong);
        }
        stack.push((ShapeNode::Value(child), depth.saturating_add(1)));
    }
    Ok(())
}

fn admit_children(
    child_count: usize,
    nodes: usize,
    retained_nodes: usize,
    max_nodes: usize,
) -> Result<(), JsonStructureError> {
    let retained = nodes.saturating_add(retained_nodes);
    if child_count > max_nodes.saturating_sub(retained) {
        return Err(JsonStructureError::TooManyNodes);
    }
    Ok(())
}
