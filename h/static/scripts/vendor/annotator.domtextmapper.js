// Generated by CoffeeScript 1.6.3
/*
** Annotator 1.2.6-dev-e2bea2d
** https://github.com/okfn/annotator/
**
** Copyright 2012 Aron Carroll, Rufus Pollock, and Nick Stenning.
** Dual licensed under the MIT and GPLv3 licenses.
** https://github.com/okfn/annotator/blob/master/LICENSE
**
** Built at: 2015-01-17 12:44:22Z
*/



/*
//
*/

// Generated by CoffeeScript 1.6.3
(function() {
  var _ref,
    __hasProp = {}.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; };

  Annotator.Plugin.DomTextMapper = (function(_super) {
    __extends(DomTextMapper, _super);

    function DomTextMapper() {
      _ref = DomTextMapper.__super__.constructor.apply(this, arguments);
      return _ref;
    }

    DomTextMapper.prototype.pluginInit = function() {
      var _this = this;
      if (this.options.skip) {
        console.log("Not registering DOM-Text-Mapper.");
        return;
      }
      this.anchoring = this.annotator.anchoring;
      return this.anchoring.documentAccessStrategies.unshift({
        name: "DOM-Text-Mapper",
        mapper: window.DomTextMapper,
        init: function() {
          return _this.anchoring.document.setRootNode(_this.annotator.wrapper[0]);
        }
      });
    };

    return DomTextMapper;

  })(Annotator.Plugin);

}).call(this);

//
//# sourceMappingURL=annotator.domtextmapper.map