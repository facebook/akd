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
//! Generated file from `src/proto/audit.proto`

use protobuf::Message as Message_imported_for_functions;
use protobuf::ProtobufEnum as ProtobufEnum_imported_for_functions;

/// Generated files are compatible only with the same version
/// of protobuf runtime.
const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_2_8_1;

#[derive(PartialEq,Clone,Default)]
pub struct NodeLabel {
    // message fields
    label_val: ::protobuf::SingularField<::std::vec::Vec<u8>>,
    label_len: ::std::option::Option<u32>,
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

    // optional bytes label_val = 1;


    pub fn get_label_val(&self) -> &[u8] {
        match self.label_val.as_ref() {
            Some(v) => &v,
            None => &[],
        }
    }
    pub fn clear_label_val(&mut self) {
        self.label_val.clear();
    }

    pub fn has_label_val(&self) -> bool {
        self.label_val.is_some()
    }

    // Param is passed by value, moved
    pub fn set_label_val(&mut self, v: ::std::vec::Vec<u8>) {
        self.label_val = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_label_val(&mut self) -> &mut ::std::vec::Vec<u8> {
        if self.label_val.is_none() {
            self.label_val.set_default();
        }
        self.label_val.as_mut().unwrap()
    }

    // Take field
    pub fn take_label_val(&mut self) -> ::std::vec::Vec<u8> {
        self.label_val.take().unwrap_or_else(|| ::std::vec::Vec::new())
    }

    // optional uint32 label_len = 2;


    pub fn get_label_len(&self) -> u32 {
        self.label_len.unwrap_or(0)
    }
    pub fn clear_label_len(&mut self) {
        self.label_len = ::std::option::Option::None;
    }

    pub fn has_label_len(&self) -> bool {
        self.label_len.is_some()
    }

    // Param is passed by value, moved
    pub fn set_label_len(&mut self, v: u32) {
        self.label_len = ::std::option::Option::Some(v);
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
                    ::protobuf::rt::read_singular_bytes_into(wire_type, is, &mut self.label_val)?;
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.label_len = ::std::option::Option::Some(tmp);
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
        if let Some(ref v) = self.label_val.as_ref() {
            my_size += ::protobuf::rt::bytes_size(1, &v);
        }
        if let Some(v) = self.label_len {
            my_size += ::protobuf::rt::value_size(2, v, ::protobuf::wire_format::WireTypeVarint);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        if let Some(ref v) = self.label_val.as_ref() {
            os.write_bytes(1, &v)?;
        }
        if let Some(v) = self.label_len {
            os.write_uint32(2, v)?;
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
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                    "label_val",
                    |m: &NodeLabel| { &m.label_val },
                    |m: &mut NodeLabel| { &mut m.label_val },
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "label_len",
                    |m: &NodeLabel| { &m.label_len },
                    |m: &mut NodeLabel| { &mut m.label_len },
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
        self.label_val.clear();
        self.label_len = ::std::option::Option::None;
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
pub struct SingleEncodedProof {
    // message fields
    inserted: ::protobuf::RepeatedField<Node>,
    unchanged: ::protobuf::RepeatedField<Node>,
    // special fields
    pub unknown_fields: ::protobuf::UnknownFields,
    pub cached_size: ::protobuf::CachedSize,
}

impl<'a> ::std::default::Default for &'a SingleEncodedProof {
    fn default() -> &'a SingleEncodedProof {
        <SingleEncodedProof as ::protobuf::Message>::default_instance()
    }
}

impl SingleEncodedProof {
    pub fn new() -> SingleEncodedProof {
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

impl ::protobuf::Message for SingleEncodedProof {
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

    fn new() -> SingleEncodedProof {
        SingleEncodedProof::new()
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
                    |m: &SingleEncodedProof| { &m.inserted },
                    |m: &mut SingleEncodedProof| { &mut m.inserted },
                ));
                fields.push(::protobuf::reflect::accessor::make_repeated_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<Node>>(
                    "unchanged",
                    |m: &SingleEncodedProof| { &m.unchanged },
                    |m: &mut SingleEncodedProof| { &mut m.unchanged },
                ));
                ::protobuf::reflect::MessageDescriptor::new::<SingleEncodedProof>(
                    "SingleEncodedProof",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }

    fn default_instance() -> &'static SingleEncodedProof {
        static mut instance: ::protobuf::lazy::Lazy<SingleEncodedProof> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const SingleEncodedProof,
        };
        unsafe {
            instance.get(SingleEncodedProof::new)
        }
    }
}

impl ::protobuf::Clear for SingleEncodedProof {
    fn clear(&mut self) {
        self.inserted.clear();
        self.unchanged.clear();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for SingleEncodedProof {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for SingleEncodedProof {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\x15src/proto/audit.proto\"E\n\tNodeLabel\x12\x1b\n\tlabel_val\x18\x01\
    \x20\x01(\x0cR\x08labelVal\x12\x1b\n\tlabel_len\x18\x02\x20\x01(\rR\x08l\
    abelLen\"<\n\x04Node\x12\x20\n\x05label\x18\x01\x20\x01(\x0b2\n.NodeLabe\
    lR\x05label\x12\x12\n\x04hash\x18\x02\x20\x01(\x0cR\x04hash\"\\\n\x12Sin\
    gleEncodedProof\x12!\n\x08inserted\x18\x01\x20\x03(\x0b2\x05.NodeR\x08in\
    serted\x12#\n\tunchanged\x18\x02\x20\x03(\x0b2\x05.NodeR\tunchanged\
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