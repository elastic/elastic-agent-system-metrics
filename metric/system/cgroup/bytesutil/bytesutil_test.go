package bytesutil

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFields(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  []string
	}{
		{
			name:  "empty array",
			input: []byte(""),
			want:  []string{},
		},
		{
			name:  "single white space",
			input: []byte(" "),
			want:  []string{"", ""},
		},
		{
			name:  "single word",
			input: []byte("hello"),
			want:  []string{"hello"},
		},
		{
			name:  "multiple words",
			input: []byte("hello world this is a test"),
			want:  []string{"hello", "world", "this", "is", "a", "test"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i, f := range Fields(tt.input) {
				require.Equal(t, tt.want[i], string(f), "Fields() mismatch at index %d", i)
			}
		})
	}
}

func TestSplit(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  []string
	}{
		{
			name:  "empty array",
			input: []byte(""),
			want:  []string{},
		},
		{
			name:  "single separator",
			input: []byte(","),
			want:  []string{"", ""},
		},
		{
			name:  "single word",
			input: []byte("hello"),
			want:  []string{"hello"},
		},
		{
			name:  "multiple words",
			input: []byte("hello,world,this,is,a,test"),
			want:  []string{"hello", "world", "this", "is", "a", "test"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i, f := range Split(tt.input, ',') {
				require.Equal(t, tt.want[i], string(f), "Split() mismatch at index %d", i)
			}
		})
	}
}
