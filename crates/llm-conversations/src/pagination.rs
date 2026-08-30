use crate::{ConversationContractError, ConversationId, ConversationMessage, MessageSequence};

/// Hard upper bound for one conversation-message page.
pub const MAX_MESSAGE_PAGE_SIZE: u16 = 100;

/// A validated non-zero message page size no greater than [`MAX_MESSAGE_PAGE_SIZE`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessagePageSize(u16);

impl MessagePageSize {
    /// Validates a caller-supplied message page size.
    ///
    /// # Errors
    ///
    /// Returns [`ConversationContractError::InvalidPagination`] for zero or values above
    /// [`MAX_MESSAGE_PAGE_SIZE`].
    pub const fn new(value: u16) -> Result<Self, ConversationContractError> {
        if value == 0 || value > MAX_MESSAGE_PAGE_SIZE {
            Err(ConversationContractError::InvalidPagination)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the bounded numeric page size.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// An opaque-by-type keyset cursor bound to one conversation and append position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageCursor {
    conversation_id: ConversationId,
    after_sequence: MessageSequence,
}

impl MessageCursor {
    /// Creates a conversation-bound keyset cursor.
    #[must_use]
    pub const fn new(conversation_id: ConversationId, after_sequence: MessageSequence) -> Self {
        Self {
            conversation_id,
            after_sequence,
        }
    }

    /// Returns the conversation to which this cursor is bound.
    #[must_use]
    pub const fn conversation_id(self) -> ConversationId {
        self.conversation_id
    }

    /// Returns the exclusive lower sequence bound.
    #[must_use]
    pub const fn after_sequence(self) -> MessageSequence {
        self.after_sequence
    }
}

/// A bounded, conversation-bound keyset pagination request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessagePageRequest {
    conversation_id: ConversationId,
    after: Option<MessageCursor>,
    limit: MessagePageSize,
}

impl MessagePageRequest {
    /// Starts a first page for one conversation.
    #[must_use]
    pub const fn first(conversation_id: ConversationId, limit: MessagePageSize) -> Self {
        Self {
            conversation_id,
            after: None,
            limit,
        }
    }

    /// Continues a page using a cursor that must belong to the same conversation.
    ///
    /// # Errors
    ///
    /// Returns [`ConversationContractError::InvalidPagination`] for a cross-conversation
    /// cursor.
    pub fn after(
        conversation_id: ConversationId,
        cursor: MessageCursor,
        limit: MessagePageSize,
    ) -> Result<Self, ConversationContractError> {
        if conversation_id == cursor.conversation_id {
            Ok(Self {
                conversation_id,
                after: Some(cursor),
                limit,
            })
        } else {
            Err(ConversationContractError::InvalidPagination)
        }
    }

    /// Returns the requested conversation identity.
    #[must_use]
    pub const fn conversation_id(self) -> ConversationId {
        self.conversation_id
    }

    /// Returns the optional exclusive keyset cursor.
    #[must_use]
    pub const fn cursor(self) -> Option<MessageCursor> {
        self.after
    }

    /// Returns the fixed page bound.
    #[must_use]
    pub const fn limit(self) -> MessagePageSize {
        self.limit
    }
}

/// One validated page of canonical conversation messages.
#[derive(Clone, Debug, PartialEq)]
pub struct MessagePage {
    items: Vec<ConversationMessage>,
    next_cursor: Option<MessageCursor>,
}

impl MessagePage {
    /// Validates ordered page contents and derives a keyset continuation cursor.
    ///
    /// # Errors
    ///
    /// Returns [`ConversationContractError::InvalidPagination`] when the page exceeds its
    /// requested bound, contains another conversation, is not strictly sequence-ordered, or
    /// claims another page after an empty result.
    pub fn new(
        request: MessagePageRequest,
        items: Vec<ConversationMessage>,
        has_more: bool,
    ) -> Result<Self, ConversationContractError> {
        if items.len() > usize::from(request.limit.get()) || (has_more && items.is_empty()) {
            return Err(ConversationContractError::InvalidPagination);
        }
        let mut prior = request.cursor().map(MessageCursor::after_sequence);
        for item in &items {
            if item.conversation_id() != request.conversation_id {
                return Err(ConversationContractError::InvalidPagination);
            }
            if prior.is_some_and(|sequence| item.sequence() <= sequence) {
                return Err(ConversationContractError::InvalidPagination);
            }
            prior = Some(item.sequence());
        }
        let next_cursor = if has_more {
            prior.map(|sequence| MessageCursor::new(request.conversation_id, sequence))
        } else {
            None
        };
        Ok(Self { items, next_cursor })
    }

    /// Borrows the ordered canonical message snapshots.
    #[must_use]
    pub fn items(&self) -> &[ConversationMessage] {
        &self.items
    }

    /// Returns the continuation cursor only when another page exists.
    #[must_use]
    pub const fn next_cursor(&self) -> Option<MessageCursor> {
        self.next_cursor
    }
}
