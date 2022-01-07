// This file is generated by rust-protobuf 2.8.1. Do not edit
// @generated

// https://github.com/Manishearth/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy::all)]

#![cfg_attr(rustfmt, rustfmt_skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unsafe_code)]
#![allow(unused_imports)]
#![allow(unused_results)]
//! Generated file from `src/proto/inter-node.proto`

use protobuf::Message as Message_imported_for_functions;
use protobuf::ProtobufEnum as ProtobufEnum_imported_for_functions;

/// Generated files are compatible only with the same version
/// of protobuf runtime.
const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_2_8_1;

#[derive(PartialEq,Clone,Default)]
pub struct NodeLabel {
    // message fields
    len: ::std::option::Option<u32>,
    val: ::std::option::Option<u64>,
    // special fields
    pub unknown_fields: ::protobuf::UnknownFields,
    pub cached_size: ::protobuf::CachedSize,
}

impl<'a> ::std::default::Default for &'a NodeLabel {
    fn default() -> &'a NodeLabel {
        <NodeLabel as ::protobuf::Message>::default_instance()
    }
}

impl NodeLabel {
    pub fn new() -> NodeLabel {
        ::std::default::Default::default()
    }

    // optional uint32 len = 1;


    pub fn get_len(&self) -> u32 {
        self.len.unwrap_or(0)
    }
    pub fn clear_len(&mut self) {
        self.len = ::std::option::Option::None;
    }

    pub fn has_len(&self) -> bool {
        self.len.is_some()
    }

    // Param is passed by value, moved
    pub fn set_len(&mut self, v: u32) {
        self.len = ::std::option::Option::Some(v);
    }

    // optional uint64 val = 2;


    pub fn get_val(&self) -> u64 {
        self.val.unwrap_or(0)
    }
    pub fn clear_val(&mut self) {
        self.val = ::std::option::Option::None;
    }

    pub fn has_val(&self) -> bool {
        self.val.is_some()
    }

    // Param is passed by value, moved
    pub fn set_val(&mut self, v: u64) {
        self.val = ::std::option::Option::Some(v);
    }
}

impl ::protobuf::Message for NodeLabel {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.len = ::std::option::Option::Some(tmp);
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint64()?;
                    self.val = ::std::option::Option::Some(tmp);
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(v) = self.len {
            my_size += ::protobuf::rt::value_size(1, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.val {
            my_size += ::protobuf::rt::value_size(2, v, ::protobuf::wire_format::WireTypeVarint);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.len {
            os.write_uint32(1, v)?;
        }
        if let Some(v) = self.val {
            os.write_uint64(2, v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &dyn (::std::any::Any) {
        self as &dyn (::std::any::Any)
    }
    fn as_any_mut(&mut self) -> &mut dyn (::std::any::Any) {
        self as &mut dyn (::std::any::Any)
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<dyn (::std::any::Any)> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        Self::descriptor_static()
    }

    fn new() -> NodeLabel {
        NodeLabel::new()
    }

    fn descriptor_static() -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "len",
                    |m: &NodeLabel| { &m.len },
                    |m: &mut NodeLabel| { &mut m.len },
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint64>(
                    "val",
                    |m: &NodeLabel| { &m.val },
                    |m: &mut NodeLabel| { &mut m.val },
                ));
                ::protobuf::reflect::MessageDescriptor::new::<NodeLabel>(
                    "NodeLabel",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }

    fn default_instance() -> &'static NodeLabel {
        static mut instance: ::protobuf::lazy::Lazy<NodeLabel> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const NodeLabel,
        };
        unsafe {
            instance.get(NodeLabel::new)
        }
    }
}

impl ::protobuf::Clear for NodeLabel {
    fn clear(&mut self) {
        self.len = ::std::option::Option::None;
        self.val = ::std::option::Option::None;
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for NodeLabel {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for NodeLabel {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct Node {
    // message fields
    label: ::protobuf::SingularPtrField<NodeLabel>,
    hash: ::protobuf::SingularField<::std::vec::Vec<u8>>,
    // special fields
    pub unknown_fields: ::protobuf::UnknownFields,
    pub cached_size: ::protobuf::CachedSize,
}

impl<'a> ::std::default::Default for &'a Node {
    fn default() -> &'a Node {
        <Node as ::protobuf::Message>::default_instance()
    }
}

impl Node {
    pub fn new() -> Node {
        ::std::default::Default::default()
    }

    // optional .NodeLabel label = 1;


    pub fn get_label(&self) -> &NodeLabel {
        self.label.as_ref().unwrap_or_else(|| NodeLabel::default_instance())
    }
    pub fn clear_label(&mut self) {
        self.label.clear();
    }

    pub fn has_label(&self) -> bool {
        self.label.is_some()
    }

    // Param is passed by value, moved
    pub fn set_label(&mut self, v: NodeLabel) {
        self.label = ::protobuf::SingularPtrField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_label(&mut self) -> &mut NodeLabel {
        if self.label.is_none() {
            self.label.set_default();
        }
        self.label.as_mut().unwrap()
    }

    // Take field
    pub fn take_label(&mut self) -> NodeLabel {
        self.label.take().unwrap_or_else(|| NodeLabel::new())
    }

    // optional bytes hash = 2;


    pub fn get_hash(&self) -> &[u8] {
        match self.hash.as_ref() {
            Some(v) => &v,
            None => &[],
        }
    }
    pub fn clear_hash(&mut self) {
        self.hash.clear();
    }

    pub fn has_hash(&self) -> bool {
        self.hash.is_some()
    }

    // Param is passed by value, moved
    pub fn set_hash(&mut self, v: ::std::vec::Vec<u8>) {
        self.hash = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_hash(&mut self) -> &mut ::std::vec::Vec<u8> {
        if self.hash.is_none() {
            self.hash.set_default();
        }
        self.hash.as_mut().unwrap()
    }

    // Take field
    pub fn take_hash(&mut self) -> ::std::vec::Vec<u8> {
        self.hash.take().unwrap_or_else(|| ::std::vec::Vec::new())
    }
}

impl ::protobuf::Message for Node {
    fn is_initialized(&self) -> bool {
        for v in &self.label {
            if !v.is_initialized() {
                return false;
            }
        };
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_message_into(wire_type, is, &mut self.label)?;
                },
                2 => {
                    ::protobuf::rt::read_singular_bytes_into(wire_type, is, &mut self.hash)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(ref v) = self.label.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        }
        if let Some(ref v) = self.hash.as_ref() {
            my_size += ::protobuf::rt::bytes_size(2, &v);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        if let Some(ref v) = self.label.as_ref() {
            os.write_tag(1, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        }
        if let Some(ref v) = self.hash.as_ref() {
            os.write_bytes(2, &v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &dyn (::std::any::Any) {
        self as &dyn (::std::any::Any)
    }
    fn as_any_mut(&mut self) -> &mut dyn (::std::any::Any) {
        self as &mut dyn (::std::any::Any)
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<dyn (::std::any::Any)> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        Self::descriptor_static()
    }

    fn new() -> Node {
        Node::new()
    }

    fn descriptor_static() -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_singular_ptr_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<NodeLabel>>(
                    "label",
                    |m: &Node| { &m.label },
                    |m: &mut Node| { &mut m.label },
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                    "hash",
                    |m: &Node| { &m.hash },
                    |m: &mut Node| { &mut m.hash },
                ));
                ::protobuf::reflect::MessageDescriptor::new::<Node>(
                    "Node",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }

    fn default_instance() -> &'static Node {
        static mut instance: ::protobuf::lazy::Lazy<Node> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const Node,
        };
        unsafe {
            instance.get(Node::new)
        }
    }
}

impl ::protobuf::Clear for Node {
    fn clear(&mut self) {
        self.label.clear();
        self.hash.clear();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for Node {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for Node {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct AppendOnlyProof {
    // message fields
    inserted: ::protobuf::RepeatedField<Node>,
    unchanged: ::protobuf::RepeatedField<Node>,
    // special fields
    pub unknown_fields: ::protobuf::UnknownFields,
    pub cached_size: ::protobuf::CachedSize,
}

impl<'a> ::std::default::Default for &'a AppendOnlyProof {
    fn default() -> &'a AppendOnlyProof {
        <AppendOnlyProof as ::protobuf::Message>::default_instance()
    }
}

impl AppendOnlyProof {
    pub fn new() -> AppendOnlyProof {
        ::std::default::Default::default()
    }

    // repeated .Node inserted = 1;


    pub fn get_inserted(&self) -> &[Node] {
        &self.inserted
    }
    pub fn clear_inserted(&mut self) {
        self.inserted.clear();
    }

    // Param is passed by value, moved
    pub fn set_inserted(&mut self, v: ::protobuf::RepeatedField<Node>) {
        self.inserted = v;
    }

    // Mutable pointer to the field.
    pub fn mut_inserted(&mut self) -> &mut ::protobuf::RepeatedField<Node> {
        &mut self.inserted
    }

    // Take field
    pub fn take_inserted(&mut self) -> ::protobuf::RepeatedField<Node> {
        ::std::mem::replace(&mut self.inserted, ::protobuf::RepeatedField::new())
    }

    // repeated .Node unchanged = 2;


    pub fn get_unchanged(&self) -> &[Node] {
        &self.unchanged
    }
    pub fn clear_unchanged(&mut self) {
        self.unchanged.clear();
    }

    // Param is passed by value, moved
    pub fn set_unchanged(&mut self, v: ::protobuf::RepeatedField<Node>) {
        self.unchanged = v;
    }

    // Mutable pointer to the field.
    pub fn mut_unchanged(&mut self) -> &mut ::protobuf::RepeatedField<Node> {
        &mut self.unchanged
    }

    // Take field
    pub fn take_unchanged(&mut self) -> ::protobuf::RepeatedField<Node> {
        ::std::mem::replace(&mut self.unchanged, ::protobuf::RepeatedField::new())
    }
}

impl ::protobuf::Message for AppendOnlyProof {
    fn is_initialized(&self) -> bool {
        for v in &self.inserted {
            if !v.is_initialized() {
                return false;
            }
        };
        for v in &self.unchanged {
            if !v.is_initialized() {
                return false;
            }
        };
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_repeated_message_into(wire_type, is, &mut self.inserted)?;
                },
                2 => {
                    ::protobuf::rt::read_repeated_message_into(wire_type, is, &mut self.unchanged)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        for value in &self.inserted {
            let len = value.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        };
        for value in &self.unchanged {
            let len = value.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        };
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        for v in &self.inserted {
            os.write_tag(1, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        };
        for v in &self.unchanged {
            os.write_tag(2, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        };
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &dyn (::std::any::Any) {
        self as &dyn (::std::any::Any)
    }
    fn as_any_mut(&mut self) -> &mut dyn (::std::any::Any) {
        self as &mut dyn (::std::any::Any)
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<dyn (::std::any::Any)> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        Self::descriptor_static()
    }

    fn new() -> AppendOnlyProof {
        AppendOnlyProof::new()
    }

    fn descriptor_static() -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_repeated_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<Node>>(
                    "inserted",
                    |m: &AppendOnlyProof| { &m.inserted },
                    |m: &mut AppendOnlyProof| { &mut m.inserted },
                ));
                fields.push(::protobuf::reflect::accessor::make_repeated_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<Node>>(
                    "unchanged",
                    |m: &AppendOnlyProof| { &m.unchanged },
                    |m: &mut AppendOnlyProof| { &mut m.unchanged },
                ));
                ::protobuf::reflect::MessageDescriptor::new::<AppendOnlyProof>(
                    "AppendOnlyProof",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }

    fn default_instance() -> &'static AppendOnlyProof {
        static mut instance: ::protobuf::lazy::Lazy<AppendOnlyProof> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const AppendOnlyProof,
        };
        unsafe {
            instance.get(AppendOnlyProof::new)
        }
    }
}

impl ::protobuf::Clear for AppendOnlyProof {
    fn clear(&mut self) {
        self.inserted.clear();
        self.unchanged.clear();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for AppendOnlyProof {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for AppendOnlyProof {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct VerifyRequest {
    // message fields
    proof: ::protobuf::SingularPtrField<AppendOnlyProof>,
    previous_hash: ::protobuf::SingularField<::std::vec::Vec<u8>>,
    new_hash: ::protobuf::SingularField<::std::vec::Vec<u8>>,
    epoch: ::std::option::Option<u64>,
    // special fields
    pub unknown_fields: ::protobuf::UnknownFields,
    pub cached_size: ::protobuf::CachedSize,
}

impl<'a> ::std::default::Default for &'a VerifyRequest {
    fn default() -> &'a VerifyRequest {
        <VerifyRequest as ::protobuf::Message>::default_instance()
    }
}

impl VerifyRequest {
    pub fn new() -> VerifyRequest {
        ::std::default::Default::default()
    }

    // optional .AppendOnlyProof proof = 1;


    pub fn get_proof(&self) -> &AppendOnlyProof {
        self.proof.as_ref().unwrap_or_else(|| AppendOnlyProof::default_instance())
    }
    pub fn clear_proof(&mut self) {
        self.proof.clear();
    }

    pub fn has_proof(&self) -> bool {
        self.proof.is_some()
    }

    // Param is passed by value, moved
    pub fn set_proof(&mut self, v: AppendOnlyProof) {
        self.proof = ::protobuf::SingularPtrField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_proof(&mut self) -> &mut AppendOnlyProof {
        if self.proof.is_none() {
            self.proof.set_default();
        }
        self.proof.as_mut().unwrap()
    }

    // Take field
    pub fn take_proof(&mut self) -> AppendOnlyProof {
        self.proof.take().unwrap_or_else(|| AppendOnlyProof::new())
    }

    // optional bytes previous_hash = 2;


    pub fn get_previous_hash(&self) -> &[u8] {
        match self.previous_hash.as_ref() {
            Some(v) => &v,
            None => &[],
        }
    }
    pub fn clear_previous_hash(&mut self) {
        self.previous_hash.clear();
    }

    pub fn has_previous_hash(&self) -> bool {
        self.previous_hash.is_some()
    }

    // Param is passed by value, moved
    pub fn set_previous_hash(&mut self, v: ::std::vec::Vec<u8>) {
        self.previous_hash = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_previous_hash(&mut self) -> &mut ::std::vec::Vec<u8> {
        if self.previous_hash.is_none() {
            self.previous_hash.set_default();
        }
        self.previous_hash.as_mut().unwrap()
    }

    // Take field
    pub fn take_previous_hash(&mut self) -> ::std::vec::Vec<u8> {
        self.previous_hash.take().unwrap_or_else(|| ::std::vec::Vec::new())
    }

    // optional bytes new_hash = 3;


    pub fn get_new_hash(&self) -> &[u8] {
        match self.new_hash.as_ref() {
            Some(v) => &v,
            None => &[],
        }
    }
    pub fn clear_new_hash(&mut self) {
        self.new_hash.clear();
    }

    pub fn has_new_hash(&self) -> bool {
        self.new_hash.is_some()
    }

    // Param is passed by value, moved
    pub fn set_new_hash(&mut self, v: ::std::vec::Vec<u8>) {
        self.new_hash = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_new_hash(&mut self) -> &mut ::std::vec::Vec<u8> {
        if self.new_hash.is_none() {
            self.new_hash.set_default();
        }
        self.new_hash.as_mut().unwrap()
    }

    // Take field
    pub fn take_new_hash(&mut self) -> ::std::vec::Vec<u8> {
        self.new_hash.take().unwrap_or_else(|| ::std::vec::Vec::new())
    }

    // optional uint64 epoch = 4;


    pub fn get_epoch(&self) -> u64 {
        self.epoch.unwrap_or(0)
    }
    pub fn clear_epoch(&mut self) {
        self.epoch = ::std::option::Option::None;
    }

    pub fn has_epoch(&self) -> bool {
        self.epoch.is_some()
    }

    // Param is passed by value, moved
    pub fn set_epoch(&mut self, v: u64) {
        self.epoch = ::std::option::Option::Some(v);
    }
}

impl ::protobuf::Message for VerifyRequest {
    fn is_initialized(&self) -> bool {
        for v in &self.proof {
            if !v.is_initialized() {
                return false;
            }
        };
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_message_into(wire_type, is, &mut self.proof)?;
                },
                2 => {
                    ::protobuf::rt::read_singular_bytes_into(wire_type, is, &mut self.previous_hash)?;
                },
                3 => {
                    ::protobuf::rt::read_singular_bytes_into(wire_type, is, &mut self.new_hash)?;
                },
                4 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint64()?;
                    self.epoch = ::std::option::Option::Some(tmp);
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(ref v) = self.proof.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        }
        if let Some(ref v) = self.previous_hash.as_ref() {
            my_size += ::protobuf::rt::bytes_size(2, &v);
        }
        if let Some(ref v) = self.new_hash.as_ref() {
            my_size += ::protobuf::rt::bytes_size(3, &v);
        }
        if let Some(v) = self.epoch {
            my_size += ::protobuf::rt::value_size(4, v, ::protobuf::wire_format::WireTypeVarint);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        if let Some(ref v) = self.proof.as_ref() {
            os.write_tag(1, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        }
        if let Some(ref v) = self.previous_hash.as_ref() {
            os.write_bytes(2, &v)?;
        }
        if let Some(ref v) = self.new_hash.as_ref() {
            os.write_bytes(3, &v)?;
        }
        if let Some(v) = self.epoch {
            os.write_uint64(4, v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &dyn (::std::any::Any) {
        self as &dyn (::std::any::Any)
    }
    fn as_any_mut(&mut self) -> &mut dyn (::std::any::Any) {
        self as &mut dyn (::std::any::Any)
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<dyn (::std::any::Any)> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        Self::descriptor_static()
    }

    fn new() -> VerifyRequest {
        VerifyRequest::new()
    }

    fn descriptor_static() -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_singular_ptr_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<AppendOnlyProof>>(
                    "proof",
                    |m: &VerifyRequest| { &m.proof },
                    |m: &mut VerifyRequest| { &mut m.proof },
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                    "previous_hash",
                    |m: &VerifyRequest| { &m.previous_hash },
                    |m: &mut VerifyRequest| { &mut m.previous_hash },
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                    "new_hash",
                    |m: &VerifyRequest| { &m.new_hash },
                    |m: &mut VerifyRequest| { &mut m.new_hash },
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint64>(
                    "epoch",
                    |m: &VerifyRequest| { &m.epoch },
                    |m: &mut VerifyRequest| { &mut m.epoch },
                ));
                ::protobuf::reflect::MessageDescriptor::new::<VerifyRequest>(
                    "VerifyRequest",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }

    fn default_instance() -> &'static VerifyRequest {
        static mut instance: ::protobuf::lazy::Lazy<VerifyRequest> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const VerifyRequest,
        };
        unsafe {
            instance.get(VerifyRequest::new)
        }
    }
}

impl ::protobuf::Clear for VerifyRequest {
    fn clear(&mut self) {
        self.proof.clear();
        self.previous_hash.clear();
        self.new_hash.clear();
        self.epoch = ::std::option::Option::None;
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for VerifyRequest {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for VerifyRequest {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct VerifyResponse {
    // message fields
    ShardPartials: ::protobuf::RepeatedField<::std::vec::Vec<u8>>,
    // special fields
    pub unknown_fields: ::protobuf::UnknownFields,
    pub cached_size: ::protobuf::CachedSize,
}

impl<'a> ::std::default::Default for &'a VerifyResponse {
    fn default() -> &'a VerifyResponse {
        <VerifyResponse as ::protobuf::Message>::default_instance()
    }
}

impl VerifyResponse {
    pub fn new() -> VerifyResponse {
        ::std::default::Default::default()
    }

    // repeated bytes ShardPartials = 1;


    pub fn get_ShardPartials(&self) -> &[::std::vec::Vec<u8>] {
        &self.ShardPartials
    }
    pub fn clear_ShardPartials(&mut self) {
        self.ShardPartials.clear();
    }

    // Param is passed by value, moved
    pub fn set_ShardPartials(&mut self, v: ::protobuf::RepeatedField<::std::vec::Vec<u8>>) {
        self.ShardPartials = v;
    }

    // Mutable pointer to the field.
    pub fn mut_ShardPartials(&mut self) -> &mut ::protobuf::RepeatedField<::std::vec::Vec<u8>> {
        &mut self.ShardPartials
    }

    // Take field
    pub fn take_ShardPartials(&mut self) -> ::protobuf::RepeatedField<::std::vec::Vec<u8>> {
        ::std::mem::replace(&mut self.ShardPartials, ::protobuf::RepeatedField::new())
    }
}

impl ::protobuf::Message for VerifyResponse {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_repeated_bytes_into(wire_type, is, &mut self.ShardPartials)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        for value in &self.ShardPartials {
            my_size += ::protobuf::rt::bytes_size(1, &value);
        };
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        for v in &self.ShardPartials {
            os.write_bytes(1, &v)?;
        };
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &dyn (::std::any::Any) {
        self as &dyn (::std::any::Any)
    }
    fn as_any_mut(&mut self) -> &mut dyn (::std::any::Any) {
        self as &mut dyn (::std::any::Any)
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<dyn (::std::any::Any)> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        Self::descriptor_static()
    }

    fn new() -> VerifyResponse {
        VerifyResponse::new()
    }

    fn descriptor_static() -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_repeated_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                    "ShardPartials",
                    |m: &VerifyResponse| { &m.ShardPartials },
                    |m: &mut VerifyResponse| { &mut m.ShardPartials },
                ));
                ::protobuf::reflect::MessageDescriptor::new::<VerifyResponse>(
                    "VerifyResponse",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }

    fn default_instance() -> &'static VerifyResponse {
        static mut instance: ::protobuf::lazy::Lazy<VerifyResponse> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const VerifyResponse,
        };
        unsafe {
            instance.get(VerifyResponse::new)
        }
    }
}

impl ::protobuf::Clear for VerifyResponse {
    fn clear(&mut self) {
        self.ShardPartials.clear();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for VerifyResponse {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for VerifyResponse {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\x1asrc/proto/inter-node.proto\"/\n\tNodeLabel\x12\x10\n\x03len\x18\
    \x01\x20\x01(\rR\x03len\x12\x10\n\x03val\x18\x02\x20\x01(\x04R\x03val\"<\
    \n\x04Node\x12\x20\n\x05label\x18\x01\x20\x01(\x0b2\n.NodeLabelR\x05labe\
    l\x12\x12\n\x04hash\x18\x02\x20\x01(\x0cR\x04hash\"Y\n\x0fAppendOnlyProo\
    f\x12!\n\x08inserted\x18\x01\x20\x03(\x0b2\x05.NodeR\x08inserted\x12#\n\
    \tunchanged\x18\x02\x20\x03(\x0b2\x05.NodeR\tunchanged\"\x8d\x01\n\rVeri\
    fyRequest\x12&\n\x05proof\x18\x01\x20\x01(\x0b2\x10.AppendOnlyProofR\x05\
    proof\x12#\n\rprevious_hash\x18\x02\x20\x01(\x0cR\x0cpreviousHash\x12\
    \x19\n\x08new_hash\x18\x03\x20\x01(\x0cR\x07newHash\x12\x14\n\x05epoch\
    \x18\x04\x20\x01(\x04R\x05epoch\"6\n\x0eVerifyResponse\x12$\n\rShardPart\
    ials\x18\x01\x20\x03(\x0cR\rShardPartials\
";

static mut file_descriptor_proto_lazy: ::protobuf::lazy::Lazy<::protobuf::descriptor::FileDescriptorProto> = ::protobuf::lazy::Lazy {
    lock: ::protobuf::lazy::ONCE_INIT,
    ptr: 0 as *const ::protobuf::descriptor::FileDescriptorProto,
};

fn parse_descriptor_proto() -> ::protobuf::descriptor::FileDescriptorProto {
    ::protobuf::parse_from_bytes(file_descriptor_proto_data).unwrap()
}

pub fn file_descriptor_proto() -> &'static ::protobuf::descriptor::FileDescriptorProto {
    unsafe {
        file_descriptor_proto_lazy.get(|| {
            parse_descriptor_proto()
        })
    }
}
