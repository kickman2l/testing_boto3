from invoke import task, Collection


@task
def autopep8(c):
    """>> Run autocorrection on python files."""
    c.run("autopep8 --in-place --max-line-length 200 --aggressive *.py --verbose")


ns = Collection()
local = Collection('local')
local.add_task(autopep8, 'autopep8')
ns.add_collection(local)
