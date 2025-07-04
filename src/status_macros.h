#ifndef SRC_MACROS_H_
#define SRC_MACROS_H_

#define RETURN_IF_ERROR(expr)            \
  {                                      \
    const absl::Status _status = (expr); \
    if (!_status.ok()) return _status;   \
  }

#define ASSIGN_OR_RETURN(...)                                \
  STATUS_MACROS_IMPL_GET_VARIADIC_(                          \
      (__VA_ARGS__, STATUS_MACROS_IMPL_ASSIGN_OR_RETURN_2_)) \
  (__VA_ARGS__)

// Helpers

#define STATUS_MACROS_IMPL_GET_VARIADIC_HELPER_(_1, _2, NAME, ...) NAME
#define STATUS_MACROS_IMPL_GET_VARIADIC_(args) \
  STATUS_MACROS_IMPL_GET_VARIADIC_HELPER_ args

#define STATUS_MACROS_IMPL_ASSIGN_OR_RETURN_2_(lhs, rexpr)                     \
  STATUS_MACROS_IMPL_ASSIGN_OR_RETURN_(                                        \
      STATUS_MACROS_IMPL_CONCAT_(_status_or_value, __LINE__), lhs, rexpr,      \
      return std::move(STATUS_MACROS_IMPL_CONCAT_(_status_or_value, __LINE__)) \
          .status())

#define STATUS_MACROS_IMPL_ASSIGN_OR_RETURN_(statusor, lhs, rexpr, \
                                             error_expression)     \
  auto statusor = (rexpr);                                         \
  if (!statusor.ok()) {                                            \
    error_expression;                                              \
  }                                                                \
  lhs = std::move(statusor).value()

#define STATUS_MACROS_IMPL_CONCAT_INNER_(x, y) x##y
#define STATUS_MACROS_IMPL_CONCAT_(x, y) STATUS_MACROS_IMPL_CONCAT_INNER_(x, y)

#endif // SRC_MACROS_H_
