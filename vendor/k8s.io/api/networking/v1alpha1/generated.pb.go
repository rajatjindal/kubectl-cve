/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: k8s.io/kubernetes/vendor/k8s.io/api/networking/v1alpha1/generated.proto

package v1alpha1

import (
	fmt "fmt"

	io "io"

	proto "github.com/gogo/protobuf/proto"
	v11 "k8s.io/api/core/v1"

	math "math"
	math_bits "math/bits"
	reflect "reflect"
	strings "strings"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

func (m *ClusterCIDRConfig) Reset()      { *m = ClusterCIDRConfig{} }
func (*ClusterCIDRConfig) ProtoMessage() {}
func (*ClusterCIDRConfig) Descriptor() ([]byte, []int) {
	return fileDescriptor_c1b7ac8d7d97acec, []int{0}
}
func (m *ClusterCIDRConfig) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *ClusterCIDRConfig) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	b = b[:cap(b)]
	n, err := m.MarshalToSizedBuffer(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}
func (m *ClusterCIDRConfig) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ClusterCIDRConfig.Merge(m, src)
}
func (m *ClusterCIDRConfig) XXX_Size() int {
	return m.Size()
}
func (m *ClusterCIDRConfig) XXX_DiscardUnknown() {
	xxx_messageInfo_ClusterCIDRConfig.DiscardUnknown(m)
}

var xxx_messageInfo_ClusterCIDRConfig proto.InternalMessageInfo

func (m *ClusterCIDRConfigList) Reset()      { *m = ClusterCIDRConfigList{} }
func (*ClusterCIDRConfigList) ProtoMessage() {}
func (*ClusterCIDRConfigList) Descriptor() ([]byte, []int) {
	return fileDescriptor_c1b7ac8d7d97acec, []int{1}
}
func (m *ClusterCIDRConfigList) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *ClusterCIDRConfigList) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	b = b[:cap(b)]
	n, err := m.MarshalToSizedBuffer(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}
func (m *ClusterCIDRConfigList) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ClusterCIDRConfigList.Merge(m, src)
}
func (m *ClusterCIDRConfigList) XXX_Size() int {
	return m.Size()
}
func (m *ClusterCIDRConfigList) XXX_DiscardUnknown() {
	xxx_messageInfo_ClusterCIDRConfigList.DiscardUnknown(m)
}

var xxx_messageInfo_ClusterCIDRConfigList proto.InternalMessageInfo

func (m *ClusterCIDRConfigSpec) Reset()      { *m = ClusterCIDRConfigSpec{} }
func (*ClusterCIDRConfigSpec) ProtoMessage() {}
func (*ClusterCIDRConfigSpec) Descriptor() ([]byte, []int) {
	return fileDescriptor_c1b7ac8d7d97acec, []int{2}
}
func (m *ClusterCIDRConfigSpec) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *ClusterCIDRConfigSpec) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	b = b[:cap(b)]
	n, err := m.MarshalToSizedBuffer(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}
func (m *ClusterCIDRConfigSpec) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ClusterCIDRConfigSpec.Merge(m, src)
}
func (m *ClusterCIDRConfigSpec) XXX_Size() int {
	return m.Size()
}
func (m *ClusterCIDRConfigSpec) XXX_DiscardUnknown() {
	xxx_messageInfo_ClusterCIDRConfigSpec.DiscardUnknown(m)
}

var xxx_messageInfo_ClusterCIDRConfigSpec proto.InternalMessageInfo

func (m *ClusterCIDRConfigStatus) Reset()      { *m = ClusterCIDRConfigStatus{} }
func (*ClusterCIDRConfigStatus) ProtoMessage() {}
func (*ClusterCIDRConfigStatus) Descriptor() ([]byte, []int) {
	return fileDescriptor_c1b7ac8d7d97acec, []int{3}
}
func (m *ClusterCIDRConfigStatus) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *ClusterCIDRConfigStatus) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	b = b[:cap(b)]
	n, err := m.MarshalToSizedBuffer(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}
func (m *ClusterCIDRConfigStatus) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ClusterCIDRConfigStatus.Merge(m, src)
}
func (m *ClusterCIDRConfigStatus) XXX_Size() int {
	return m.Size()
}
func (m *ClusterCIDRConfigStatus) XXX_DiscardUnknown() {
	xxx_messageInfo_ClusterCIDRConfigStatus.DiscardUnknown(m)
}

var xxx_messageInfo_ClusterCIDRConfigStatus proto.InternalMessageInfo

func init() {
	proto.RegisterType((*ClusterCIDRConfig)(nil), "k8s.io.api.networking.v1alpha1.ClusterCIDRConfig")
	proto.RegisterType((*ClusterCIDRConfigList)(nil), "k8s.io.api.networking.v1alpha1.ClusterCIDRConfigList")
	proto.RegisterType((*ClusterCIDRConfigSpec)(nil), "k8s.io.api.networking.v1alpha1.ClusterCIDRConfigSpec")
	proto.RegisterType((*ClusterCIDRConfigStatus)(nil), "k8s.io.api.networking.v1alpha1.ClusterCIDRConfigStatus")
}

func init() {
	proto.RegisterFile("k8s.io/kubernetes/vendor/k8s.io/api/networking/v1alpha1/generated.proto", fileDescriptor_c1b7ac8d7d97acec)
}

var fileDescriptor_c1b7ac8d7d97acec = []byte{
	// 550 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x94, 0xcd, 0x6e, 0xd3, 0x4c,
	0x14, 0x86, 0xe3, 0xb4, 0xa9, 0xf2, 0x4d, 0xf3, 0xd1, 0x62, 0x09, 0x35, 0x64, 0xe1, 0x44, 0x59,
	0x75, 0x01, 0x33, 0xa4, 0x2a, 0x81, 0x2d, 0x4e, 0x25, 0x88, 0xc4, 0x4f, 0xe5, 0x4a, 0x45, 0x42,
	0x48, 0x30, 0x71, 0x4e, 0x9d, 0x21, 0xb1, 0xc7, 0x9a, 0x19, 0x07, 0xb1, 0xe3, 0x0a, 0x10, 0x77,
	0xc2, 0x6d, 0x64, 0x83, 0xd4, 0x65, 0x57, 0x11, 0x31, 0x37, 0x82, 0x66, 0xe2, 0x26, 0x69, 0xdd,
	0x16, 0xba, 0xf3, 0x39, 0xf3, 0xbc, 0xef, 0xf9, 0x99, 0x91, 0xd1, 0xf3, 0xe1, 0x53, 0x89, 0x19,
	0x27, 0xc3, 0xa4, 0x07, 0x22, 0x02, 0x05, 0x92, 0x8c, 0x21, 0xea, 0x73, 0x41, 0xb2, 0x03, 0x1a,
	0x33, 0x12, 0x81, 0xfa, 0xcc, 0xc5, 0x90, 0x45, 0x01, 0x19, 0xb7, 0xe8, 0x28, 0x1e, 0xd0, 0x16,
	0x09, 0x20, 0x02, 0x41, 0x15, 0xf4, 0x71, 0x2c, 0xb8, 0xe2, 0xb6, 0x33, 0xe7, 0x31, 0x8d, 0x19,
	0x5e, 0xf2, 0xf8, 0x9c, 0xaf, 0x3d, 0x0c, 0x98, 0x1a, 0x24, 0x3d, 0xec, 0xf3, 0x90, 0x04, 0x3c,
	0xe0, 0xc4, 0xc8, 0x7a, 0xc9, 0x89, 0x89, 0x4c, 0x60, 0xbe, 0xe6, 0x76, 0xb5, 0xe6, 0x4a, 0x79,
	0x9f, 0x0b, 0x20, 0xe3, 0x5c, 0xc9, 0xda, 0xfe, 0x92, 0x09, 0xa9, 0x3f, 0x60, 0x11, 0x88, 0x2f,
	0x24, 0x1e, 0x06, 0x3a, 0x21, 0x49, 0x08, 0x8a, 0x5e, 0xa5, 0x22, 0xd7, 0xa9, 0x44, 0x12, 0x29,
	0x16, 0x42, 0x4e, 0xd0, 0xfe, 0x9b, 0x40, 0xfa, 0x03, 0x08, 0xe9, 0x65, 0x5d, 0xf3, 0x47, 0x11,
	0xdd, 0xed, 0x8c, 0x12, 0xa9, 0x40, 0x74, 0xba, 0x07, 0x5e, 0x87, 0x47, 0x27, 0x2c, 0xb0, 0x3f,
	0xa2, 0xb2, 0xee, 0xac, 0x4f, 0x15, 0xad, 0x5a, 0x0d, 0x6b, 0x77, 0x73, 0xef, 0x11, 0x5e, 0xae,
	0x6e, 0x51, 0x00, 0xc7, 0xc3, 0x40, 0x27, 0x24, 0xd6, 0x34, 0x1e, 0xb7, 0xf0, 0x9b, 0xde, 0x27,
	0xf0, 0xd5, 0x2b, 0x50, 0xd4, 0xb5, 0x27, 0xd3, 0x7a, 0x21, 0x9d, 0xd6, 0xd1, 0x32, 0xe7, 0x2d,
	0x5c, 0xed, 0xb7, 0x68, 0x5d, 0xc6, 0xe0, 0x57, 0x8b, 0xc6, 0xfd, 0x31, 0xbe, 0xf9, 0x62, 0x70,
	0xae, 0xc5, 0xa3, 0x18, 0x7c, 0xb7, 0x92, 0x95, 0x58, 0xd7, 0x91, 0x67, 0x0c, 0xed, 0x0f, 0x68,
	0x43, 0x2a, 0xaa, 0x12, 0x59, 0x5d, 0x33, 0xd6, 0x4f, 0x6e, 0x6f, 0x6d, 0xe4, 0xee, 0x9d, 0xcc,
	0x7c, 0x63, 0x1e, 0x7b, 0x99, 0x6d, 0xf3, 0xa7, 0x85, 0xee, 0xe5, 0x34, 0x2f, 0x99, 0x54, 0xf6,
	0xfb, 0xdc, 0xd6, 0xf0, 0xbf, 0x6d, 0x4d, 0xab, 0xcd, 0xce, 0xb6, 0xb3, 0x9a, 0xe5, 0xf3, 0xcc,
	0xca, 0xc6, 0x8e, 0x51, 0x89, 0x29, 0x08, 0x65, 0xb5, 0xd8, 0x58, 0xdb, 0xdd, 0xdc, 0x6b, 0xdd,
	0x7a, 0x2e, 0xf7, 0xff, 0xcc, 0xbd, 0xd4, 0xd5, 0x3e, 0xde, 0xdc, 0xae, 0xf9, 0xad, 0x78, 0xc5,
	0x3c, 0x7a, 0xa1, 0xf6, 0x31, 0xaa, 0x44, 0xbc, 0x0f, 0x47, 0x30, 0x02, 0x5f, 0x71, 0x91, 0xcd,
	0xd4, 0x58, 0x2d, 0xac, 0x5f, 0xbd, 0x9e, 0xe0, 0xf5, 0x0a, 0xe7, 0x6e, 0xa7, 0xd3, 0x7a, 0x65,
	0x35, 0xe3, 0x5d, 0xf0, 0xb1, 0x9f, 0xa1, 0xad, 0x18, 0x84, 0x06, 0x5e, 0x70, 0xa9, 0x5c, 0xa6,
	0xa4, 0x79, 0x06, 0x25, 0x77, 0x27, 0x6b, 0x70, 0xeb, 0xf0, 0xe2, 0xb1, 0x77, 0x99, 0xb7, 0x1f,
	0xa0, 0x32, 0x8b, 0xc7, 0xfb, 0xba, 0x61, 0x73, 0xcf, 0xff, 0x2d, 0x57, 0xd7, 0x3d, 0x9c, 0xe7,
	0xbd, 0x05, 0x91, 0xd1, 0x6d, 0x43, 0xaf, 0xe7, 0xe8, 0xf6, 0x82, 0x36, 0x5f, 0xcd, 0xfb, 0x68,
	0xe7, 0xba, 0x37, 0x71, 0x30, 0x99, 0x39, 0x85, 0xd3, 0x99, 0x53, 0x38, 0x9b, 0x39, 0x85, 0xaf,
	0xa9, 0x63, 0x4d, 0x52, 0xc7, 0x3a, 0x4d, 0x1d, 0xeb, 0x2c, 0x75, 0xac, 0x5f, 0xa9, 0x63, 0x7d,
	0xff, 0xed, 0x14, 0xde, 0x39, 0x37, 0xff, 0x95, 0xfe, 0x04, 0x00, 0x00, 0xff, 0xff, 0x6c, 0x03,
	0xd9, 0x8f, 0xcf, 0x04, 0x00, 0x00,
}

func (m *ClusterCIDRConfig) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ClusterCIDRConfig) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *ClusterCIDRConfig) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	{
		size, err := m.Status.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintGenerated(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0x1a
	{
		size, err := m.Spec.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintGenerated(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0x12
	{
		size, err := m.ObjectMeta.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintGenerated(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0xa
	return len(dAtA) - i, nil
}

func (m *ClusterCIDRConfigList) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ClusterCIDRConfigList) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *ClusterCIDRConfigList) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Items) > 0 {
		for iNdEx := len(m.Items) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.Items[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintGenerated(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0x12
		}
	}
	{
		size, err := m.ListMeta.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintGenerated(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0xa
	return len(dAtA) - i, nil
}

func (m *ClusterCIDRConfigSpec) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ClusterCIDRConfigSpec) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *ClusterCIDRConfigSpec) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	i -= len(m.IPv6CIDR)
	copy(dAtA[i:], m.IPv6CIDR)
	i = encodeVarintGenerated(dAtA, i, uint64(len(m.IPv6CIDR)))
	i--
	dAtA[i] = 0x22
	i -= len(m.IPv4CIDR)
	copy(dAtA[i:], m.IPv4CIDR)
	i = encodeVarintGenerated(dAtA, i, uint64(len(m.IPv4CIDR)))
	i--
	dAtA[i] = 0x1a
	i = encodeVarintGenerated(dAtA, i, uint64(m.PerNodeHostBits))
	i--
	dAtA[i] = 0x10
	if m.NodeSelector != nil {
		{
			size, err := m.NodeSelector.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintGenerated(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *ClusterCIDRConfigStatus) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ClusterCIDRConfigStatus) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *ClusterCIDRConfigStatus) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	return len(dAtA) - i, nil
}

func encodeVarintGenerated(dAtA []byte, offset int, v uint64) int {
	offset -= sovGenerated(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *ClusterCIDRConfig) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = m.ObjectMeta.Size()
	n += 1 + l + sovGenerated(uint64(l))
	l = m.Spec.Size()
	n += 1 + l + sovGenerated(uint64(l))
	l = m.Status.Size()
	n += 1 + l + sovGenerated(uint64(l))
	return n
}

func (m *ClusterCIDRConfigList) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = m.ListMeta.Size()
	n += 1 + l + sovGenerated(uint64(l))
	if len(m.Items) > 0 {
		for _, e := range m.Items {
			l = e.Size()
			n += 1 + l + sovGenerated(uint64(l))
		}
	}
	return n
}

func (m *ClusterCIDRConfigSpec) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.NodeSelector != nil {
		l = m.NodeSelector.Size()
		n += 1 + l + sovGenerated(uint64(l))
	}
	n += 1 + sovGenerated(uint64(m.PerNodeHostBits))
	l = len(m.IPv4CIDR)
	n += 1 + l + sovGenerated(uint64(l))
	l = len(m.IPv6CIDR)
	n += 1 + l + sovGenerated(uint64(l))
	return n
}

func (m *ClusterCIDRConfigStatus) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	return n
}

func sovGenerated(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozGenerated(x uint64) (n int) {
	return sovGenerated(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (this *ClusterCIDRConfig) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&ClusterCIDRConfig{`,
		`ObjectMeta:` + strings.Replace(strings.Replace(fmt.Sprintf("%v", this.ObjectMeta), "ObjectMeta", "v1.ObjectMeta", 1), `&`, ``, 1) + `,`,
		`Spec:` + strings.Replace(strings.Replace(this.Spec.String(), "ClusterCIDRConfigSpec", "ClusterCIDRConfigSpec", 1), `&`, ``, 1) + `,`,
		`Status:` + strings.Replace(strings.Replace(this.Status.String(), "ClusterCIDRConfigStatus", "ClusterCIDRConfigStatus", 1), `&`, ``, 1) + `,`,
		`}`,
	}, "")
	return s
}
func (this *ClusterCIDRConfigList) String() string {
	if this == nil {
		return "nil"
	}
	repeatedStringForItems := "[]ClusterCIDRConfig{"
	for _, f := range this.Items {
		repeatedStringForItems += strings.Replace(strings.Replace(f.String(), "ClusterCIDRConfig", "ClusterCIDRConfig", 1), `&`, ``, 1) + ","
	}
	repeatedStringForItems += "}"
	s := strings.Join([]string{`&ClusterCIDRConfigList{`,
		`ListMeta:` + strings.Replace(strings.Replace(fmt.Sprintf("%v", this.ListMeta), "ListMeta", "v1.ListMeta", 1), `&`, ``, 1) + `,`,
		`Items:` + repeatedStringForItems + `,`,
		`}`,
	}, "")
	return s
}
func (this *ClusterCIDRConfigSpec) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&ClusterCIDRConfigSpec{`,
		`NodeSelector:` + strings.Replace(fmt.Sprintf("%v", this.NodeSelector), "NodeSelector", "v11.NodeSelector", 1) + `,`,
		`PerNodeHostBits:` + fmt.Sprintf("%v", this.PerNodeHostBits) + `,`,
		`IPv4CIDR:` + fmt.Sprintf("%v", this.IPv4CIDR) + `,`,
		`IPv6CIDR:` + fmt.Sprintf("%v", this.IPv6CIDR) + `,`,
		`}`,
	}, "")
	return s
}
func (this *ClusterCIDRConfigStatus) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&ClusterCIDRConfigStatus{`,
		`}`,
	}, "")
	return s
}
func valueToStringGenerated(v interface{}) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("*%v", pv)
}
func (m *ClusterCIDRConfig) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowGenerated
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ClusterCIDRConfig: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ClusterCIDRConfig: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ObjectMeta", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthGenerated
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.ObjectMeta.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Spec", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthGenerated
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.Spec.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Status", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthGenerated
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.Status.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipGenerated(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthGenerated
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *ClusterCIDRConfigList) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowGenerated
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ClusterCIDRConfigList: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ClusterCIDRConfigList: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ListMeta", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthGenerated
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.ListMeta.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Items", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthGenerated
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Items = append(m.Items, ClusterCIDRConfig{})
			if err := m.Items[len(m.Items)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipGenerated(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthGenerated
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *ClusterCIDRConfigSpec) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowGenerated
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ClusterCIDRConfigSpec: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ClusterCIDRConfigSpec: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field NodeSelector", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthGenerated
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.NodeSelector == nil {
				m.NodeSelector = &v11.NodeSelector{}
			}
			if err := m.NodeSelector.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field PerNodeHostBits", wireType)
			}
			m.PerNodeHostBits = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.PerNodeHostBits |= int32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field IPv4CIDR", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthGenerated
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.IPv4CIDR = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field IPv6CIDR", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthGenerated
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.IPv6CIDR = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipGenerated(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthGenerated
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *ClusterCIDRConfigStatus) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowGenerated
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ClusterCIDRConfigStatus: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ClusterCIDRConfigStatus: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		default:
			iNdEx = preIndex
			skippy, err := skipGenerated(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthGenerated
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipGenerated(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowGenerated
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthGenerated
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupGenerated
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthGenerated
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthGenerated        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowGenerated          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupGenerated = fmt.Errorf("proto: unexpected end of group")
)
