class ThreadingService
  # Mix in message thread properties into the prototype. The body of the
  # class will overwrite any methods applied here. If you need inheritance
  # assign the message thread to a local varible.
  $.extend(this.prototype, mail.messageThread())

  root: null

  this.$inject = ['$rootScope']
  constructor: ($rootScope) ->
    # Create a root container.
    @root = mail.messageContainer()
    $rootScope.$on('beforeAnnotationCreated', this.beforeAnnotationCreated)
    $rootScope.$on('annotationDeleted', this.annotationDeleted)
    $rootScope.$on('annotationsLoaded', this.annotationsLoaded)

  # TODO: Refactor the jwz API for progressive updates.
  # Right now the idTable is wiped when `messageThread.thread()` is called and
  # empty containers are pruned. We want to show empties so that replies attach
  # to missing parents and threads can be updates as new data arrives.
  thread: (messages) ->
    for message in messages
      # Get or create a thread to contain the annotation
      if message.id
        thread = (this.getContainer message.id)
        thread.message = message
      else
        # XXX: relies on outside code to update the idTable if the message
        # later acquires an id.
        thread = mail.messageContainer(message)

      prev = @root

      references = message.references or []
      if typeof(message.references) == 'string'
        references = [references]

      # Build out an ancestry from the root
      for reference in references
        container = this.getContainer(reference)
        unless container.parent? or container.hasDescendant(prev)  # no cycles
          prev.addChild(container)
        prev = container

      # Attach the thread at its leaf location
      unless thread.hasDescendant(prev)  # no cycles
        do ->
          for child in prev.children when child.message is message
            return  # no dupes
          prev.addChild(thread)

    this.pruneEmpties(@root)
    @root

  pruneEmpties: (parent) ->
    for container in parent.children
      this.pruneEmpties(container)

      if !container.message && container.children.length == 0
        parent.removeChild(container)

  beforeAnnotationCreated: (event, annotation) =>
    this.thread([annotation])

  annotationDeleted: (event, {id}) =>
    container = this.getContainer id
    container.message = null
    this.pruneEmpties(@root)

  annotationsLoaded: (event, annotations) =>
    messages = (@root.flattenChildren() or []).concat(annotations)
    this.thread(messages)

angular.module('h').service('threading', ThreadingService)
