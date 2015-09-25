title: Streams & Lambdas in Java 8
theme: sjaakvandenberg/cleaver-light
--
# Streams & Lambdas in Java 8

--

### Sorting


```java
public class Person {
    private String lastName;
    private String firstName;
    /* getter, setter, constructor */
}

List<Person> persons = Arrays.asList(
    new Person("Doe", "John"),
    new Person("Stronach", "Frank"),
    new Person("Stark", "Tony"),
    new Person("Stark", "Abigail")
);

// Doe John
// Stark Abigail
// Stark Tony
// Stronach Frank
```

--

### Sorting: Anonymous Class

< Java 8

```java
Collections.sort(persons, new Comparator<Person>() {
    @Override
    public int compare(Person person1, Person person2) {
        int lastNameComparison = person1
          .getLastName()
          .compareTo(person2.getLastName());

        if (lastNameComparison == 0) {
            return person1
              .getFirstName()
              .compareTo(person2.getFirstName());
        } else {
            return lastNameComparison;
        }
    }
});
```

--

### Sorting: Lambdas
IntelliJ: ALT + Enter -> replace with lambda

Types are optional (inferred)

```java
persons.sort((person1, person2) -> {
    int lastNameComparison = person1
      .getLastName()
      .compareTo(person2.getLastName());
    if (lastNameComparison == 0) {
        return person1
          .getFirstName()
          .compareTo(person2.getFirstName());
    } else {
        return lastNameComparison;
    }
});
```

--
### Lambda Syntax
Lambda Type signature denoted using a single **abstract** method interface
```java
@FunctionalInterface
interface Identity<T> {
    T identity(T in);
}

public static <T> List<T> map (List<T> list, Identity<T> f) {
    ArrayList<T> newList = new ArrayList<T>();
    for (T item: list) {
        newList.add(f.identity(item));
    }
    return newList;
}

Identity<String> lambda = in -> in;
map(persons, lambda).forEach(System.out::println);  

```

--

### Lambda Scopes

Local variables may be referenced but must be final:

```java
final int constInt = 3;
List<Integer> intList = Arrays.asList(1, 2, 3);
intList.replaceAll(value -> value + constInt);
```

Fields and static variables can be accessed just fine:
```java
static int constInt = 3;
private int constInt2 = 4;

List<Integer> intList = Arrays.asList(1, 2, 3);
intList.replaceAll(value -> value + constInt + this.constInt2);
```

--

### Built-In Interfaces

* **Predicate< T \>**: takes a T and returns a boolean
* **Consumer< T \>**:  takes a T and returns void
* **Supplier< T \>**:  takes nothing and returns T
* **Function < T, R >**: takes a T and returns an R
* **UnaryOperator < T >**: takes a T and returns a T (similar to Identity Interface)
* [and many more](https://docs.oracle.com/javase/8/docs/api/java/util/function/package-summary.html)

--

### Built-In Interface default methods
Interfaces can contain default methods since Java 8

```java
Predicate<String> predicate = (s) -> s.length() > 0;
predicate.test("hi");  // true

// chaining functions (composing also possible)
Function<String, Integer> toInt = Integer::valueOf;
Function<String, String> toStr = toInt.andThen(String::valueOf);
```
--

### Sorting: Comparator
Lambda enhanced Class

```java
import java.util.Comparator;

persons.sort(
  comparing(Person::getLastName)
  .thenComparing(Person::getFirstName)
);

persons.forEach(System.out::println);
```

--

### Streams

Stream = sequence of elements on which one or more operations can be performed

Pure = does not change the elements of the list but returns a new instance

Either **terminal** (returns a result) or **intermediate** (returns a Stream)

```java
persons.stream()
  .filter(p -> p.getLastName().startsWith("St"))  // intermediate
  .forEach(System.out::println);  // terminal

// or
Predicate<Person> st = p -> p.getLastName().startsWith("St");

persons.stream()
  .filter(st)
  .forEach(System.out::println);
```

--

### Stream Intermediate Operations

* map
* filter
* distinct
* flatMap
* limit
* skip
* mapToInt/mapToLong/mapToDouble

--

### flatMap

```java
List<String> phrases = Arrays.asList(
  "sporadic perjury",
  "confounded skimming",
  "incumbent jailer",
  "confounded jailer"
);

List<String> uniqueWords = phrases
  .stream()
  .flatMap(phrase -> Stream.of(phrase.split(" +")))
  .distinct()
  .collect(Collectors.toList());

System.out.println("Unique words: " + uniqueWords);
// Unique words: [confounded, incumbent, jailer, perjury, skimming, sporadic]
```

--

### Stream Terminal Operations

* collect
* count
* allMatch/anyMatch/noneMatch
* find/findFirst/findAny
* forEach/forEachOrdered
* max
* min
* reduce

IntStream/DoubleStream/LongStream
* sum
* average

--
### Group By

```java
List<Person> persons = Arrays.asList(
  new Person("Doe", "John"),
  new Person("Stronach", "Frank"),
  new Person("Stark", "Toni"),
  new Person("Stark", "Abigail"),
  new Person("Stronach", "Abigail")
);

persons.stream()
  .filter(p -> p.getFirstName().contains("i"))
  .collect(Collectors.groupingBy(Person::getLastName))
  .forEach((lastName, members) -> System.out.println(lastName + " " + members.size()));

// Stronach 1
// Stark 2
```

--

### Parallel Streams
Very easy to add, roughly 30% faster

Attention: order not defined with forEach!

```java
persons.parallelStream()
  .filter(p -> p.getLastName().startsWith("St"))
  .sorted(comparing(Person::getLastName).thenComparing(Person::getFirstName))
  .forEach(System.out::println);
```

Not always printed in order!

--

### Parallel Streams Order

You are responsible for handling Thread safety.

Beware of Side effects! Use pure functions!

Don't modify the data source in the stream (persons), don't rely on state from outer scope

```java
persons.parallelStream()
  .filter(p -> p.getLastName().startsWith("St"))
  .sorted(comparing(Person::getLastName).thenComparing(Person::getFirstName))
  .forEachOrdered(System.out::println);
```

--

### Stream Fusion
Streams automatically use Stream Fusion, meaning the following two operations are the same:

```java
persons.parallelStream()
  .filter(p -> p.getLastName().startsWith("St"))
  .filter(p -> p.getFirstName().startsWith("Fr"))

persons.parallelStream()
  .filter(p -> p.getLastName().startsWith("St") &&
          p -> p.getFirstName().startsWith("Fr"))
```

--

### Sources To Read Up

* [http://winterbe.com/posts/2014/03/16/java-8-tutorial/](http://winterbe.com/posts/2014/03/16/java-8-tutorial/)
* [http://winterbe.com/posts/2014/07/31/java8-stream-tutorial-examples/](http://winterbe.com/posts/2014/07/31/java8-stream-tutorial-examples/)
