   function getBotResponse() {
      var rawText = $("#textInput").val();
      var userHtml = '<div class="ChatItem ChatItem--expert"><div class="ChatItem-chatText">' + rawText + "</div></div>";
      $("#textInput").val("");
      $("#chatbox").append(userHtml);
      document
        .getElementById("userInput")
        .scrollIntoView({ block: "start", behavior: "smooth" });
      $.get("/get", { msg: rawText }).done(function (data) {
        var botHtml = '<div class="ChatItem ChatItem--customer"><div class="ChatItem-chatText">' + data + "</div></div>";
        $("#chatbox").append(botHtml);
        document
          .getElementById("userInput")
          .scrollIntoView({ block: "start", behavior: "smooth" });
      });
    }
    $("#textInput").keypress(function (e) {
      if (e.which == 13) {
        getBotResponse();
      }
    });

