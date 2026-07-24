package com.sba301.cinemaai.dto.response;

import com.sba301.cinemaai.util.MessageTranslator;
import java.time.LocalDateTime;
import java.util.List;

public record ErrorResponse(
        boolean success,
        String message,
        String path,
        List<FieldErrorResponse> errors,
        LocalDateTime timestamp
) {

    public ErrorResponse {
        message = MessageTranslator.translate(message);
    }

    public static ErrorResponse of(String message, String path) {
        return new ErrorResponse(false, message, path, List.of(), java.time.LocalDateTime.now(java.time.ZoneId.of("Asia/Ho_Chi_Minh")));
    }

    public static ErrorResponse of(String message, String path, List<FieldErrorResponse> errors) {
        return new ErrorResponse(false, message, path, errors, java.time.LocalDateTime.now(java.time.ZoneId.of("Asia/Ho_Chi_Minh")));
    }
}
