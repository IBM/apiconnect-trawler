
import logging
import time
import watch_pods
import kubernetes

watcher = watch_pods.Watcher(True)

fake_pod = kubernetes.client.V1Pod(
        metadata=kubernetes.client.V1ObjectMeta(
            name='testpod', 
            namespace='trawler-test',
            annotations={"testAnnotation": "testValue"}
        ),
        status=kubernetes.client.V1PodStatus(
            conditions=[
                kubernetes.client.V1PodCondition(type='Ready', status=True)
            ],
            pod_ip="127.0.0.1"
        )
    )


watch_events = [{"object":fake_pod, "type":"ADDED"}]

def test_watch(caplog, mocker):
    caplog.set_level(logging.INFO)
    #mocker.patch('time.sleep', side_effect=KeyboardInterrupt())
    #with pytest.raises(KeyboardInterrupt):
    assert not watcher.enabled 

def test_pod_ready():
    pod_ready = kubernetes.client.V1Pod(status=kubernetes.client.V1PodStatus(conditions=[
        kubernetes.client.V1PodCondition(type='Ready', status=True)
    ]))
    pod_not_ready = kubernetes.client.V1Pod(status=kubernetes.client.V1PodStatus(conditions=[
        kubernetes.client.V1PodCondition(type='Ready', status=False)
    ]))
    assert watcher.podReady(pod_ready)
    assert not watcher.podReady(pod_not_ready)

def test_register(caplog, mocker):
    caplog.set_level(logging.INFO)
    mocker.patch('time.sleep', side_effect=KeyboardInterrupt())
    watcher.register('test','testAnnotation','testValue')
    assert watcher.enabled
    assert 'testAnnotation' in caplog.text

def test_watch(caplog, mocker):
    caplog.set_level(logging.INFO)
    mocker.patch('kubernetes.watch.Watch.stream',
                 return_value=watch_events
                 )
    mocker.patch('kubernetes.client.CoreV1Api.list_pod_for_all_namespaces',
                 return_value=kubernetes.client.V1PodList(items=[fake_pod])
                 )
    watcher.register('test','testAnnotation','testValue')
    assert watcher.enabled
    assert 'testAnnotation' in caplog.text
    assert 0 == len(watcher.getPods('test'))
    watcher.start()
    time.sleep(8)
    assert 1 == len(watcher.getPods('test'))
    assert kubernetes.client.CoreV1Api.list_pod_for_all_namespaces

def test_watch_error(caplog, mocker):
    caplog.set_level(logging.INFO)
    mocker.patch('kubernetes.watch.Watch.stream',
                 side_effect=kubernetes.client.rest.ApiException('error'),
                 return_value=watch_events
                 )    
    mocker.patch('kubernetes.client.CoreV1Api.list_pod_for_all_namespaces',
                 side_effect=kubernetes.client.rest.ApiException('error')
                 )
    watcher.register('test','testAnnotation','testValue')
    assert watcher.enabled
    assert 'testAnnotation' in caplog.text
    assert 0 == len(watcher.getPods('test'))
    watcher.start()
    assert kubernetes.client.CoreV1Api.list_pod_for_all_namespaces


