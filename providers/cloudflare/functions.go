package cloudflare

import (
	"regexp"
	"strconv"
	"strings"
	"fmt"
)

var unsafeChars = regexp.MustCompile(`[^0-9A-Za-z_]`)
var unsafeChars1 = regexp.MustCompile(`[^0-9A-Za-z]`)

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func escapeRune(s string) string {
	res := regexp.MustCompile(s)
	return fmt.Sprintf(res.ReplaceAllString("-", "-"))
}

func TfSanitize(name string) string {
	name = unsafeChars.ReplaceAllStringFunc(name, escapeRune)
	return name
}

func escapeRuner(s string) string {
	res := regexp.MustCompile(s)
	return fmt.Sprintf(res.ReplaceAllString(" ", "-"))
}

func escapeRuner1(s string) string {
	res := regexp.MustCompile(s)
	return fmt.Sprintf(res.ReplaceAllString(s, "-"))
}

func TfSanitizes(name string) string {
	name = unsafeChars.ReplaceAllStringFunc(name, escapeRune)
	return name
}

func TfSanitizes1(name string) string {
	name = unsafeChars1.ReplaceAllStringFunc(name, escapeRuner1)
	return name
}

func coincidences(word string, list []string) []string{
	coincidences := []string{}
    for item := range list {
		matched, err := regexp.MatchString(word,list[item])
		if err == nil {
			if matched {
				coincidences = append(coincidences, list[item])
			}
		}
    }
	return coincidences
}

func maxnumcoincidences(list []string) int{
	numbers := make([]int, 0)
	for i := range list {
		// separa el recurso por -
		split := strings.Split(list[i], "-")
		// obten el ultimo valor de la separacion
		lastvalue := split[len(split)-1]
		//si el ultimo valor se puede convertir a entero añadelo a numbers
		number, err := strconv.Atoi(lastvalue)
		if err == nil {
			numbers = append(numbers, number)
		}else {
			numbers = append(numbers, 0)
		}
	}

	max := numbers[0] // assume first value is the smallest
	for _, value := range numbers { //(omite el indice), para cada valor en numbers
		if value > max { //si el valor es mayor que el maximo
			max = value // found another smaller value, replace previous value in max
		}
	}
	return max
}